import { prisma, User } from './generated/prisma-client';
import datamodelInfo from './generated/nexus-prisma';

import { prismaObjectType, makePrismaSchema } from 'nexus-prisma';
import { PrismaObjectDefinitionBlock } from 'nexus-prisma/dist/blocks/objectType';
import { stringArg, idArg, objectType } from 'nexus';
import {
  NexusObjectTypeDef,
  NexusWrappedType,
  ObjectDefinitionBlock
} from 'nexus/dist/core';

import { GraphQLServer } from 'graphql-yoga';
import { ContextParameters } from 'graphql-yoga/dist/types';
import { GraphQLSchema } from 'graphql';

import { rule, shield } from 'graphql-shield';
import { Rule } from 'graphql-shield/dist/rules';
import { IMiddlewareGenerator } from 'graphql-middleware';

import * as path from 'path';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { jwtConfig } from './config';

function getClaims(req: ContextParameters): object | null {
  let decoded: object;
  try {
    const authHeader: string = req.request.get('Authorization') || '';
    const [type, token] = authHeader.split(' ');
    if (type === 'Bearer' && token) {
      decoded = jwt.verify(token, jwtConfig.JWT_SECRET) as object;
    } else {
      return null;
    }
  } catch (e) {
    return null;
  }
  return decoded;
}

const isAuthenticated: Rule = rule()(
  async (_parent, _args, ctx, _info): Promise<boolean> => {
    return ctx.claims !== null;
  }
);

const permissions: IMiddlewareGenerator<any, any, any> = shield({
  Query: {
    user: isAuthenticated,
    todosByUser: isAuthenticated
  },
  Mutation: {
    deleteTodo: isAuthenticated,
    promoteUser: isAuthenticated,
    createTodo: isAuthenticated,
    completeTodo: isAuthenticated
  }
});

type UserLoginPayloadType = NexusObjectTypeDef<'UserLoginPayload'>;
type UserLoginPayloadDefinition = ObjectDefinitionBlock<'UserLoginPayload'>;

const UserLoginPayload: UserLoginPayloadType = objectType({
  name: 'UserLoginPayload',
  definition: (t: UserLoginPayloadDefinition): void => {
    t.field('user', { type: 'User' });
    t.string('token');
  }
});

type QueryType = NexusWrappedType<NexusObjectTypeDef<'Query'>>;
type QueryDefinition = PrismaObjectDefinitionBlock<'Query'>;

const Query: QueryType = prismaObjectType({
  name: 'Query',
  definition: (t: QueryDefinition): void => {
    t.prismaFields(['user']);

    t.list.field('todosByUser', {
      type: 'Todo',
      resolve: (_, _args, ctx) => ctx.prisma.user({ id: ctx.claims.id }).todos()
    });
  }
});

type MutationType = NexusWrappedType<NexusObjectTypeDef<'Mutation'>>;
type MutationDefinition = PrismaObjectDefinitionBlock<'Mutation'>;

const Mutation: MutationType = prismaObjectType({
  name: 'Mutation',
  definition: (t: MutationDefinition): void => {
    t.prismaFields(['deleteTodo']);

    t.field('loginUser', {
      type: UserLoginPayload,
      args: {
        username: stringArg({ nullable: false }),
        password: stringArg({ nullable: false })
      },
      resolve: async (_, { username, password }, ctx) => {
        const { passwordHash, ...user } = await ctx.prisma.user({
          name: username
        });
        const isPasswordValid: boolean = await bcrypt.compare(
          password,
          passwordHash
        );
        if (isPasswordValid) {
          const token: string = jwt.sign(user, jwtConfig.JWT_SECRET, {
            expiresIn: '30m'
          });
          return { user, token };
        } else {
          throw new Error('Password was not correct.');
        }
      }
    });

    t.field('registerUser', {
      type: UserLoginPayload,
      args: {
        username: stringArg({ nullable: false }),
        password: stringArg({ nullable: false })
      },
      resolve: async (_, { username, password }, ctx) => {
        const existingUser: User = await ctx.prisma.user({
          name: username
        });
        if (existingUser) {
          throw new Error('This user already exists!');
        }
        const hashed: string = await bcrypt.hash(password, 10);
        const { passwordHash, ...user } = ctx.prisma.createUser({
          name: username,
          passwordHash: hashed
        });
        const token: string = jwt.sign(user, jwtConfig.JWT_SECRET);
        return { user, token };
      }
    });

    t.field('promoteUser', {
      type: 'User',
      args: {
        id: idArg({ nullable: false })
      },
      resolve: (_, { id }, ctx) => {
        if (!ctx.claims.admin) {
          throw new Error('Must be logged in as an admin.');
        }
        return ctx.prisma.updateUser({
          where: { id },
          data: { admin: true }
        });
      }
    });

    t.field('createTodo', {
      type: 'Todo',
      args: {
        text: stringArg({ nullable: false }),
        userId: idArg({ nullable: false })
      },
      resolve: (_, { text, userId }, ctx) =>
        ctx.prisma.createTodo({
          text,
          user: { connect: { id: userId } }
        })
    });

    t.field('completeTodo', {
      type: 'Todo',
      args: {
        id: idArg({ nullable: false })
      },
      resolve: (_, { id }, ctx) =>
        ctx.prisma.updateTodo({
          where: { id },
          data: { complete: true }
        })
    });
  }
});

const schema: GraphQLSchema = makePrismaSchema({
  types: [Query, Mutation, UserLoginPayload],

  prisma: {
    datamodelInfo,
    client: prisma
  },

  outputs: {
    schema: path.join(__dirname, './generated/schema.graphql'),
    typegen: path.join(__dirname, './generated/nexus.ts')
  }
});

const server = new GraphQLServer({
  schema,
  middlewares: [permissions],
  context: (req: ContextParameters) => ({
    ...req,
    prisma,
    claims: getClaims(req)
  })
});

server.start(
  (): void => console.log('Server is running on http://localhost:4000')
);
