// Custom resolver for mutations
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { randomBytes } = require('crypto');
const { promisify } = require('util');
const { transport, makeANiceEmail } = require('../mail');
const { hasPermission } = require('../utils');
const stripe = require('../stripe');

const generateJWT = (userId, res) => {
    const token = jwt.sign({ userId }, process.env.APP_SECRET);
    res.cookie('token', token, {
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 24 * 365,
    });
}

const Mutations = {
    async createItem(parent, args, ctx, info){
        if(!ctx.request.userId){
            throw new Error(`You need to login`);
        }
        const item = await ctx.db.mutation.createItem({
            data:{
                user: {
                    connect: {
                        id: ctx.request.userId
                    }
                },
                ...args
            }
        }, info);
        return item;
    },

    async updateItem(parent, args, ctx, info){
        const updates = { ...args };
        delete updates.id;
        return await ctx.db.mutation.updateItem({
            data: updates,
            where:{
                id:args.id
            },
        } , info);
    },

    async deleteItem(parent, args, ctx, info){
        const where = { id:args.id },
              item = await ctx.db.query.item({ where }, `{id title user { id }}`);
        const ownsItem =  item.user.id === ctx.request.userId;
        const hasPermissions = ctx.request.user.permissions.some(permission => ['ADMIN', 'ITEMDELETE'].includes(permission));
        if(!ownsItem && !hasPermissions){
            throw new Error("You don't have permissions");
        }
        return ctx.db.mutation.deleteItem({ where }, info);
    },
    async signup(parent, args, ctx, info){
        args.email = args.email.toLowerCase();
        const password = await bcrypt.hash(args.password, 10);
        const user = await ctx.db.mutation.createUser({
            data:{
                ...args,
                password,
                permissions: { set: ['USER'] },
            },
        }, info);
        const token = jwt.sign({ userId : user.id}, process.env.APP_SECRET);
        ctx.response.cookie('token', token, {
            httpOnly: true,
            maxAge: 1000 * 60 * 60 * 24 * 365,
        });
        return user;
    },
    async signin(parent, { email, password }, ctx, info){
        const user = await ctx.db.query.user({ where: { email } });
        if(!user){
            throw new Error(`Incorrect email or password`);
        }
        const isValid =  await bcrypt.compare(password,user.password);
        if(!isValid){
            throw new Error(`Incorrect email or password`);
        }
        const token = jwt.sign({ userId : user.id}, process.env.APP_SECRET);
        ctx.response.cookie('token', token, {
            httpOnly: true,
            maxAge: 1000 * 60 * 60 * 24 * 365,
        });
        return user;
    },

    signout(parent, args, ctx, info){
        ctx.response.clearCookie('token');
        return { message: "Good Bye!"};
    },
    async requestReset(parent, { email }, ctx, info){
        const user = await ctx.db.query.user({ where: { email } });
        if(!user){
            throw new Error(`No such user found for email ${email}`);
        }
        const resetToken = (await promisify(randomBytes)(20)).toString('hex');
        const resetTokenExpiry = Date.now() + 3600000;
        const res = await ctx.db.mutation.updateUser({
            where: { email },
            data: { resetToken,resetTokenExpiry }
        });
        const mailRes = await transport.sendMail({
            from: 'enrique.acuna@gmail.com',
            to: user.email,
            subject: 'Your Passrword Reset',
            html: makeANiceEmail(`<a href="${process.env.FRONTEND_URL}/reset?resetToken=${resetToken}">Click here to reset your password </a>`),
        });
        return { message: "Reset sent!"};
    },
    async resetPassword(parent, args, ctx, info) {
        // 1. check if the passwords match
        if (args.password !== args.confirmPassword) {
          throw new Error("Passwords don't match!");
        }
        // 2. check if its a legit reset token
        // 3. Check if its expired
        const [user] = await ctx.db.query.users({
          where: {
            resetToken: args.resetToken,
            resetTokenExpiry_gte: Date.now() - 3600000,
          },
        });
        if (!user) {
          throw new Error('This token is either invalid or expired!');
        }
        // 4. Hash their new password
        const password = await bcrypt.hash(args.password, 10);
        // 5. Save the new password to the user and remove old resetToken fields
        const updatedUser = await ctx.db.mutation.updateUser({
          where: { email: user.email },
          data: {
            password,
            resetToken: null,
            resetTokenExpiry: null,
          },
        });
        // 6. Generate JWT
        generateJWT(updatedUser.id,ctx.response);
        // 8. return the new user
        return updatedUser;
      },
      async updatePermissions(parent, args, ctx, info) {
        // 1. Check if they are logged in
        if (!ctx.request.userId) {
          throw new Error('You must be logged in!');
        }
        // 2. Query the current user
        const currentUser = await ctx.db.query.user(
          {
            where: {
              id: ctx.request.userId,
            },
          },
          info
        );
        // 3. Check if they have permissions to do this
        hasPermission(currentUser, ['ADMIN', 'PERMISSIONUPDATE']);
        // 4. Update the permissions
        return ctx.db.mutation.updateUser(
          {
            data: {
              permissions: {
                set: args.permissions,
              },
            },
            where: {
              id: args.userId,
            },
          },
          info
        );
      },
      async addToCart(parent, args, ctx, info) {
          const { userId } = ctx.request;
          if (!userId) {
            throw new Error('You must be logged in!');
          }
          const [existingCartItem] = await ctx.db.query.cartItems({
              where: {
                  user: { id: userId },
                  item: { id: args.id },
              }
          });
          if (existingCartItem) {
            return ctx.db.mutation.updateCartItem(
              {
                where: { id: existingCartItem.id },
                data: { quantity: existingCartItem.quantity + 1 },
              },
              info
            );
          }
          return await ctx.db.mutation.createCartItem({
              data:{
                user: {
                    connect:{ id: userId },
                },
                item: {
                    connect:{ id: args.id },
                },
              }
          }, info);
      },
      async removeFromCart(parent, args, ctx, info) {
        // 1. Find the cart item
        const cartItem = await ctx.db.query.cartItem(
          {
            where: {
              id: args.id,
            },
          },
          `{ id, user { id }}`
        );
        // 1.5 Make sure we found an item
        if (!cartItem) throw new Error('No CartItem Found!');
        // 2. Make sure they own that cart item
        if (cartItem.user.id !== ctx.request.userId) {
          throw new Error('Operation unallowed');
        }
        // 3. Delete that cart item
        return ctx.db.mutation.deleteCartItem(
          {
            where: { id: args.id },
          },
          info
        );
      },
      async createOrder(parent, args, ctx, info) {
        // 1. Query the current user and make sure they are signed in
        const { userId } = ctx.request;
        if (!userId) throw new Error('You must be signed in to complete this order.');
        const user = await ctx.db.query.user(
          { where: { id: userId } },
          `{
          id
          name
          email
          cart {
            id
            quantity
            item { title price id description image largeImage }
          }}`
        );
        // 2. recalculate the total for the price
        const amount = user.cart.reduce(
          (tally, cartItem) => tally + cartItem.item.price * cartItem.quantity,
          0
        );
        // 3. Create the stripe charge (turn token into $$$)
        const charge = await stripe.charges.create({
          amount,
          currency: 'USD',
          source: args.token,
        });
        // 4. Convert the CartItems to OrderItems
        const orderItems = user.cart.map(cartItem => {
          const orderItem = {
            ...cartItem.item,
            quantity: cartItem.quantity,
            user: { connect: { id: userId } },
          };
          delete orderItem.id;
          return orderItem;
        });
    
        // 5. create the Order
        const order = await ctx.db.mutation.createOrder({
          data: {
            total: charge.amount,
            charge: charge.id,
            items: { create: orderItems },
            user: { connect: { id: userId } },
          },
        });
        // 6. Clean up - clear the users cart, delete cartItems
        const cartItemIds = user.cart.map(cartItem => cartItem.id);
        await ctx.db.mutation.deleteManyCartItems({
          where: {
            id_in: cartItemIds,
          },
        });
        // 7. Return the Order to the client
        return order;
      },
};

module.exports = Mutations;
