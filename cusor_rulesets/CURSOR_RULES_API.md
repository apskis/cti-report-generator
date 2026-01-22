# Cursor AI Development Rules - Backend API Development

**IMPORTANT NOTES:**

1. **These are guidelines, not requirements**: Use what's relevant to your project. If you're not using Docker, ignore Docker sections. If you're using Fastify instead of Express, adapt the patterns.

2. **Framework Agnostic**: While examples use Express.js, the principles apply to any framework:
   - **Node.js**: Express, Fastify, Koa, Hapi, NestJS
   - **Python**: Flask, FastAPI, Django REST Framework
   - **Go**: Gin, Echo, Chi
   - **Rust**: Actix, Rocket, Axum

3. **API Architecture Styles**: RESTful is common but not the only option:
   - **REST**: Most common, resource-based, HTTP methods
   - **GraphQL**: Query language, single endpoint, flexible queries
   - **gRPC**: High-performance, Protocol Buffers, streaming
   - **WebSocket**: Real-time, bidirectional communication
   - **tRPC**: Type-safe RPC for TypeScript full-stack apps

4. **Authentication Libraries**: Many options beyond manual JWT:
   - **Passport.js** (Node.js) - Supports 500+ strategies (OAuth, JWT, local, etc.)
   - **OAuth providers**: Auth0, Firebase Auth, Supabase Auth, AWS Cognito
   - **NextAuth.js** (for Next.js)
   - **Clerk** (modern auth as a service)
   - **Lucia** (lightweight, flexible auth)

This guide provides patterns and principles. Adapt to your chosen stack.
## Authentication Strategies & Libraries

### 86. Passport.js (Node.js Multi-Strategy Auth)

Passport supports 500+ authentication strategies (OAuth, JWT, local, SAML, etc.)
```typescript
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import { Strategy as JwtStrategy, ExtractJwt } from 'passport-jwt';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';

// Local strategy (email/password)
passport.use(new LocalStrategy(
  { usernameField: 'email' },
  async (email, password, done) => {
    try {
      const user = await userService.findByEmail(email);
      if (!user || !(await verifyPassword(password, user.password))) {
        return done(null, false, { message: 'Invalid credentials' });
      }
      return done(null, user);
    } catch (error) {
      return done(error);
    }
  }
));

// JWT strategy
passport.use(new JwtStrategy(
  {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_SECRET,
  },
  async (payload, done) => {
    try {
      const user = await userService.findById(payload.userId);
      if (!user) return done(null, false);
      return done(null, user);
    } catch (error) {
      return done(error);
    }
  }
));

// Google OAuth strategy
passport.use(new GoogleStrategy(
  {
    clientID: process.env.GOOGLE_CLIENT_ID!,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
    callbackURL: '/auth/google/callback',
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      // Find or create user based on Google profile
      let user = await userService.findByGoogleId(profile.id);
      
      if (!user) {
        user = await userService.create({
          googleId: profile.id,
          email: profile.emails?.[0]?.value,
          name: profile.displayName,
        });
      }
      
      return done(null, user);
    } catch (error) {
      return done(error);
    }
  }
));

// Routes
app.post('/auth/login', 
  passport.authenticate('local', { session: false }),
  (req, res) => {
    const token = generateJWT(req.user);
    res.json({ token, user: req.user });
  }
);

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { session: false }),
  (req, res) => {
    const token = generateJWT(req.user);
    res.redirect(`/auth-success?token=${token}`);
  }
);

// Protected route
app.get('/api/profile',
  passport.authenticate('jwt', { session: false }),
  (req, res) => {
    res.json({ user: req.user });
  }
);
```

**When to use Passport.js:**
- Need multiple auth strategies (local, OAuth, SAML)
- Social login (Google, Facebook, GitHub, Twitter)
- Enterprise SSO
- Want battle-tested, mature solution

### 87. OAuth 2.0 / OpenID Connect

OAuth is for authorization (access delegation), OpenID Connect adds authentication layer.

**Popular OAuth Providers:**
- **Auth0**: Full-featured, easy setup, generous free tier
- **Firebase Auth**: Google's solution, good for mobile
- **Supabase Auth**: Open-source Firebase alternative
- **AWS Cognito**: AWS ecosystem
- **Clerk**: Modern, great DX, built for React/Next.js
- **WorkOS**: Enterprise SSO (SAML, SCIM)

**Example with Auth0:**
```typescript
// Install: npm install express-oauth2-jwt-bearer

import { auth } from 'express-oauth2-jwt-bearer';

// Validate JWT from Auth0
const checkJwt = auth({
  audience: process.env.AUTH0_AUDIENCE,
  issuerBaseURL: `https://${process.env.AUTH0_DOMAIN}`,
});

// Protected route
app.get('/api/private', checkJwt, (req, res) => {
  // req.auth contains decoded JWT
  res.json({ userId: req.auth.sub });
});
```

**When to use OAuth providers:**
- Don't want to manage auth yourself (security, maintenance)
- Need social login
- Need enterprise features (SSO, MFA)
- Want to focus on business logic

### 88. NextAuth.js (for Next.js)

Authentication library specifically for Next.js applications.
```typescript
// pages/api/auth/[...nextauth].ts
import NextAuth from 'next-auth';
import GoogleProvider from 'next-auth/providers/google';
import CredentialsProvider from 'next-auth/providers/credentials';

export default NextAuth({
  providers: [
    GoogleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
    }),
    CredentialsProvider({
      name: 'Credentials',
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" }
      },
      async authorize(credentials) {
        const user = await verifyUser(credentials.email, credentials.password);
        if (user) return user;
        return null;
      }
    })
  ],
  callbacks: {
    async jwt({ token, user }) {
      if (user) token.userId = user.id;
      return token;
    },
    async session({ session, token }) {
      session.userId = token.userId;
      return session;
    }
  }
});

// In your API route
import { getServerSession } from 'next-auth/next';

export async function GET(req: Request) {
  const session = await getServerSession(authOptions);
  
  if (!session) {
    return new Response('Unauthorized', { status: 401 });
  }
  
  // User is authenticated
  return Response.json({ user: session.user });
}
```

### 89. Session-based vs Token-based Auth

**Session-based (Traditional)**
- Server stores session data (in memory, Redis, database)
- Client receives session ID (in cookie)
- Pros: Can invalidate immediately, simpler client
- Cons: Harder to scale horizontally, requires storage
```typescript
import session from 'express-session';
import RedisStore from 'connect-redis';

app.use(session({
  store: new RedisStore({ client: redisClient }),
  secret: process.env.SESSION_SECRET!,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true, // HTTPS only
    httpOnly: true, // No JS access
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'strict',
  }
}));

app.post('/login', async (req, res) => {
  const user = await verifyCredentials(req.body.email, req.body.password);
  if (user) {
    req.session.userId = user.id;
    res.json({ success: true });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});
```

**Token-based (Modern)**
- Server doesn't store session (stateless)
- Client receives JWT (in Authorization header or httpOnly cookie)
- Pros: Scales horizontally, works across domains
- Cons: Can't invalidate until expiry (use short TTLs + refresh tokens)

**When to use each:**
- Session-based: Traditional web apps, need instant logout, single domain
- Token-based: APIs, mobile apps, microservices, cross-domain

### 90. Social Login Providers

**Google OAuth:**
```typescript
// With Passport.js (shown above)
// Or with OAuth library directly
import { google } from 'googleapis';

const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  'http://localhost:3000/auth/google/callback'
);

app.get('/auth/google', (req, res) => {
  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: ['profile', 'email']
  });
  res.redirect(url);
});

app.get('/auth/google/callback', async (req, res) => {
  const { code } = req.query;
  const { tokens } = await oauth2Client.getToken(code);
  oauth2Client.setCredentials(tokens);
  
  const oauth2 = google.oauth2({ version: 'v2', auth: oauth2Client });
  const { data } = await oauth2.userinfo.get();
  
  // Find or create user
  let user = await userService.findByGoogleId(data.id);
  if (!user) {
    user = await userService.create({
      googleId: data.id,
      email: data.email,
      name: data.name,
    });
  }
  
  const token = generateJWT(user);
  res.redirect(`/auth-success?token=${token}`);
});
```

**GitHub, Facebook, Twitter:** Similar patterns with respective SDKs

### 91. Multi-Factor Authentication (MFA)

**Time-based One-Time Password (TOTP)**
```typescript
import speakeasy from 'speakeasy';
import QRCode from 'qrcode';

// Generate secret for user
export async function setupMFA(userId: string) {
  const secret = speakeasy.generateSecret({
    name: `MyApp (${userId})`,
  });
  
  // Save secret to user record
  await userService.update(userId, {
    mfaSecret: secret.base32,
    mfaEnabled: false, // Not enabled until verified
  });
  
  // Generate QR code for user to scan
  const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url!);
  
  return { secret: secret.base32, qrCode: qrCodeUrl };
}

// Verify MFA token
export async function verifyMFA(userId: string, token: string): Promise<boolean> {
  const user = await userService.findById(userId);
  
  if (!user?.mfaSecret) return false;
  
  return speakeasy.totp.verify({
    secret: user.mfaSecret,
    encoding: 'base32',
    token,
    window: 2, // Allow 2 steps before/after for clock drift
  });
}

// Login flow with MFA
app.post('/auth/login', async (req, res) => {
  const user = await verifyCredentials(req.body.email, req.body.password);
  
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  if (user.mfaEnabled) {
    // Create temporary token for MFA verification
    const tempToken = generateJWT({ userId: user.id, type: 'mfa-pending' }, '5m');
    return res.json({ requiresMFA: true, tempToken });
  }
  
  // No MFA required
  const token = generateJWT(user);
  res.json({ token, user });
});

app.post('/auth/verify-mfa', authenticate, async (req, res) => {
  // Check that token is MFA-pending type
  if (req.user.type !== 'mfa-pending') {
    return res.status(400).json({ error: 'Invalid token' });
  }
  
  const isValid = await verifyMFA(req.user.userId, req.body.token);
  
  if (!isValid) {
    return res.status(401).json({ error: 'Invalid MFA code' });
  }
  
  // MFA verified - issue real token
  const user = await userService.findById(req.user.userId);
  const token = generateJWT(user);
  res.json({ token, user });
});
```

### Authentication Decision Tree
```
Need auth? →
  
  Just email/password? →
    Simple app → Manual JWT (covered earlier)
    Want MFA, password reset, etc. → Auth0 / Supabase / Clerk
  
  Need social login? →
    Next.js app → NextAuth.js
    Other Node.js → Passport.js
    Managed service → Auth0 / Firebase / Clerk
  
  Need enterprise SSO (SAML)? →
    Passport.js (passport-saml) OR Auth0 / WorkOS
  
  Multi-strategy (local + OAuth + SAML)? →
    Passport.js (most flexible)
  
  Want simplest managed solution? →
    Clerk (best DX) or Supabase (open-source)
```

## Containerization (Optional)

### Docker - Use When Needed

Docker is useful but not required for all projects:

**When to use Docker:**
- Multiple services (API + database + Redis + workers)
- Ensure consistency across dev/staging/prod environments
- Deploy to cloud services that support containers (AWS ECS, Google Cloud Run, Azure Container Instances)
- Microservices architecture
- Team has different OS/environments

**When Docker might be overkill:**
- Simple single-service API
- Deploying to platform-as-a-service (Vercel, Netlify, Railway, Render)
- Small team on same OS
- Just learning - focus on code first

**Alternative deployment options:**
- **PaaS**: Vercel, Netlify, Railway, Render, Fly.io (no Docker needed, git push to deploy)
- **Serverless**: AWS Lambda, Cloudflare Workers, Vercel Functions
- **Traditional**: VPS with Node.js installed, PM2 for process management

### 82. Docker (If Using)
```dockerfile
# Multi-stage build for smaller image
FROM node:18-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

FROM node:18-alpine

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

COPY --from=builder /app/dist ./dist

EXPOSE 3000
CMD ["node", "dist/server.js"]
```

**docker-compose.yml for local development:**
```yaml
version: '3.8'

services:
  api:
    build: .
    ports:
      - "3000:3000"
    environment:
      - DATABASE_URL=postgresql://user:pass@db:5432/myapp
      - REDIS_URL=redis://redis:6379
    depends_on:
      - db
      - redis
    volumes:
      - .:/app  # Hot reload in dev
      - /app/node_modules

  db:
    image: postgres:15-alpine
    environment:
      POSTGRES_USER: user
      POSTGRES_PASSWORD: pass
      POSTGRES_DB: myapp
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data

volumes:
  postgres_data:
  redis_data:
```

But remember: **You don't need Docker to build a great API!** Start simple, add complexity only when needed.


## GraphQL-Specific Architecture

### GraphQL Project Structure
```
my-graphql-api/
├── src/
│   ├── schema/                     # GraphQL schema files
│   │   ├── types/                  # Type definitions
│   │   │   ├── user.graphql
│   │   │   ├── post.graphql
│   │   │   └── comment.graphql
│   │   ├── queries/                # Query definitions
│   │   │   ├── user.queries.graphql
│   │   │   └── post.queries.graphql
│   │   ├── mutations/              # Mutation definitions
│   │   │   ├── user.mutations.graphql
│   │   │   └── post.mutations.graphql
│   │   ├── subscriptions/          # Real-time subscriptions
│   │   │   └── post.subscriptions.graphql
│   │   └── schema.graphql          # Combined schema
│   ├── resolvers/                  # Resolver implementations
│   │   ├── queries/
│   │   │   ├── user.queries.ts
│   │   │   └── post.queries.ts
│   │   ├── mutations/
│   │   │   ├── user.mutations.ts
│   │   │   └── post.mutations.ts
│   │   ├── subscriptions/
│   │   │   └── post.subscriptions.ts
│   │   ├── fields/                 # Field-level resolvers
│   │   │   ├── user.fields.ts
│   │   │   └── post.fields.ts
│   │   └── index.ts
│   ├── dataloaders/                # DataLoader for batching
│   │   ├── user.loader.ts
│   │   └── post.loader.ts
│   ├── services/                   # Business logic
│   │   ├── user.service.ts
│   │   └── post.service.ts
│   ├── repositories/               # Data access
│   │   ├── user.repository.ts
│   │   └── post.repository.ts
│   ├── middleware/                 # GraphQL middleware
│   │   ├── auth.ts
│   │   ├── validation.ts
│   │   └── rate-limit.ts
│   ├── directives/                 # Custom directives
│   │   ├── auth.directive.ts
│   │   └── deprecated.directive.ts
│   ├── plugins/                    # Apollo/GraphQL plugins
│   │   ├── logging.plugin.ts
│   │   └── complexity.plugin.ts
│   └── server.ts                   # GraphQL server setup
├── codegen.yml                     # GraphQL Code Generator config
└── schema.graphql                  # Generated schema
```

### GraphQL Implementation (Apollo Server)
```typescript
// server.ts
import { ApolloServer } from '@apollo/server';
import { startStandaloneServer } from '@apollo/server/standalone';
import { makeExecutableSchema } from '@graphql-tools/schema';
import { loadFilesSync } from '@graphql-tools/load-files';
import { mergeTypeDefs, mergeResolvers } from '@graphql-tools/merge';
import { createContext } from './context';
import { resolvers } from './resolvers';

// Load schema files
const typesArray = loadFilesSync('src/schema/**/*.graphql');
const typeDefs = mergeTypeDefs(typesArray);

// Create executable schema
const schema = makeExecutableSchema({
  typeDefs,
  resolvers,
});

// Create Apollo Server
const server = new ApolloServer({
  schema,
  plugins: [
    loggingPlugin,
    complexityPlugin({ maxComplexity: 1000 }),
  ],
});

const { url } = await startStandaloneServer(server, {
  context: createContext,
  listen: { port: 4000 },
});

console.log(`🚀 Server ready at ${url}`);
```

### GraphQL Schema Example
```graphql
# schema/types/user.graphql
type User {
  id: ID!
  email: String!
  name: String!
  posts: [Post!]!
  createdAt: DateTime!
}

# schema/queries/user.queries.graphql
extend type Query {
  user(id: ID!): User
  users(limit: Int = 10, offset: Int = 0): [User!]!
  me: User
}

# schema/mutations/user.mutations.graphql
extend type Mutation {
  createUser(input: CreateUserInput!): User!
  updateUser(id: ID!, input: UpdateUserInput!): User!
  deleteUser(id: ID!): Boolean!
}

input CreateUserInput {
  email: String!
  name: String!
  password: String!
}

input UpdateUserInput {
  email: String
  name: String
}
```

### GraphQL Resolvers
```typescript
// resolvers/queries/user.queries.ts
import { GraphQLError } from 'graphql';

export const userQueries = {
  user: async (_parent: any, { id }: { id: string }, context: Context) => {
    if (!context.user) {
      throw new GraphQLError('Not authenticated', {
        extensions: { code: 'UNAUTHENTICATED' },
      });
    }
    
    return context.dataloaders.userLoader.load(id);
  },
  
  users: async (
    _parent: any,
    { limit, offset }: { limit: number; offset: number },
    context: Context
  ) => {
    return context.services.userService.getUsers({ limit, offset });
  },
  
  me: async (_parent: any, _args: any, context: Context) => {
    if (!context.user) {
      throw new GraphQLError('Not authenticated', {
        extensions: { code: 'UNAUTHENTICATED' },
      });
    }
    
    return context.dataloaders.userLoader.load(context.user.id);
  },
};

// resolvers/mutations/user.mutations.ts
export const userMutations = {
  createUser: async (
    _parent: any,
    { input }: { input: CreateUserInput },
    context: Context
  ) => {
    return context.services.userService.createUser(input);
  },
  
  updateUser: async (
    _parent: any,
    { id, input }: { id: string; input: UpdateUserInput },
    context: Context
  ) => {
    // Check authorization
    if (context.user?.id !== id && context.user?.role !== 'admin') {
      throw new GraphQLError('Not authorized', {
        extensions: { code: 'FORBIDDEN' },
      });
    }
    
    return context.services.userService.updateUser(id, input);
  },
};

// resolvers/fields/user.fields.ts - Field-level resolvers
export const userFields = {
  User: {
    posts: async (parent: User, _args: any, context: Context) => {
      // This runs for every User.posts field
      // Use DataLoader to batch requests
      return context.dataloaders.postsByUserLoader.load(parent.id);
    },
  },
};
```

### DataLoader (Solve N+1 Problem)
```typescript
// dataloaders/user.loader.ts
import DataLoader from 'dataloader';

export function createUserLoader(userRepository: UserRepository) {
  return new DataLoader<string, User>(async (ids) => {
    const users = await userRepository.findByIds(Array.from(ids));
    
    // DataLoader expects results in same order as ids
    const userMap = new Map(users.map(u => [u.id, u]));
    return ids.map(id => userMap.get(id) || null);
  });
}

// dataloaders/posts-by-user.loader.ts
export function createPostsByUserLoader(postRepository: PostRepository) {
  return new DataLoader<string, Post[]>(async (userIds) => {
    const posts = await postRepository.findByUserIds(Array.from(userIds));
    
    // Group posts by userId
    const postsByUser = new Map<string, Post[]>();
    for (const post of posts) {
      const existing = postsByUser.get(post.userId) || [];
      postsByUser.set(post.userId, [...existing, post]);
    }
    
    return userIds.map(userId => postsByUser.get(userId) || []);
  });
}
```

### GraphQL Context
```typescript
// context.ts
export interface Context {
  user: User | null;
  services: {
    userService: UserService;
    postService: PostService;
  };
  dataloaders: {
    userLoader: DataLoader<string, User>;
    postsByUserLoader: DataLoader<string, Post[]>;
  };
}

export async function createContext({ req }: { req: Request }): Promise<Context> {
  // Authenticate user from token
  const token = req.headers.authorization?.replace('Bearer ', '');
  const user = token ? await verifyToken(token) : null;
  
  return {
    user,
    services: {
      userService: new UserService(userRepository),
      postService: new PostService(postRepository),
    },
    dataloaders: {
      userLoader: createUserLoader(userRepository),
      postsByUserLoader: createPostsByUserLoader(postRepository),
    },
  };
}
```

### GraphQL Subscriptions (Real-time)
```typescript
// schema/subscriptions/post.subscriptions.graphql
extend type Subscription {
  postCreated: Post!
  postUpdated(id: ID!): Post!
}

// resolvers/subscriptions/post.subscriptions.ts
import { PubSub } from 'graphql-subscriptions';

const pubsub = new PubSub();

export const postSubscriptions = {
  postCreated: {
    subscribe: () => pubsub.asyncIterator(['POST_CREATED']),
  },
  
  postUpdated: {
    subscribe: (_parent: any, { id }: { id: string }) => {
      return pubsub.asyncIterator([`POST_UPDATED_${id}`]);
    },
  },
};

// In mutation, publish event
export const createPost = async (
  _parent: any,
  { input }: { input: CreatePostInput },
  context: Context
) => {
  const post = await context.services.postService.createPost(input);
  
  // Publish to subscribers
  pubsub.publish('POST_CREATED', { postCreated: post });
  
  return post;
};
```

### GraphQL Directives
```typescript
// directives/auth.directive.ts
import { mapSchema, getDirective, MapperKind } from '@graphql-tools/utils';
import { GraphQLError } from 'graphql';

export function authDirective(directiveName: string = 'auth') {
  return {
    authDirectiveTypeDefs: `directive @${directiveName}(requires: Role = USER) on OBJECT | FIELD_DEFINITION`,
    
    authDirectiveTransformer: (schema: GraphQLSchema) => {
      return mapSchema(schema, {
        [MapperKind.OBJECT_FIELD]: (fieldConfig) => {
          const authDirective = getDirective(schema, fieldConfig, directiveName)?.[0];
          
          if (authDirective) {
            const { requires } = authDirective;
            const { resolve = defaultFieldResolver } = fieldConfig;
            
            fieldConfig.resolve = function (source, args, context, info) {
              if (!context.user) {
                throw new GraphQLError('Not authenticated');
              }
              
              if (requires && context.user.role !== requires) {
                throw new GraphQLError('Not authorized');
              }
              
              return resolve(source, args, context, info);
            };
          }
          
          return fieldConfig;
        },
      });
    },
  };
}

// Usage in schema
type Query {
  users: [User!]! @auth(requires: ADMIN)
  me: User @auth
}
```

### GraphQL Best Practices

**92. Use DataLoader to prevent N+1 queries**: Batch and cache database requests.

**93. Limit query complexity**: Prevent expensive queries that could DoS your server.
```typescript
import { createComplexityPlugin } from '@escape.tech/graphql-armor';

const server = new ApolloServer({
  schema,
  plugins: [
    createComplexityPlugin({ maxComplexity: 1000 }),
  ],
});
```

**94. Implement pagination**: Use cursor-based pagination for GraphQL.
```graphql
type Query {
  users(first: Int, after: String): UserConnection!
}

type UserConnection {
  edges: [UserEdge!]!
  pageInfo: PageInfo!
}

type UserEdge {
  node: User!
  cursor: String!
}

type PageInfo {
  hasNextPage: Boolean!
  endCursor: String
}
```

**95. Use fragments for reusable selections**:
```graphql
fragment UserBasic on User {
  id
  name
  email
}

query GetUser {
  user(id: "123") {
    ...UserBasic
    posts {
      id
      title
    }
  }
}
```

---

## tRPC with Next.js Setup

### tRPC Project Structure (Next.js App Router)
```
my-trpc-app/
├── src/
│   ├── app/                        # Next.js App Router
│   │   ├── api/
│   │   │   └── trpc/
│   │   │       └── [trpc]/
│   │   │           └── route.ts    # tRPC endpoint
│   │   ├── (dashboard)/
│   │   │   └── page.tsx
│   │   └── layout.tsx
│   ├── server/                     # Backend (tRPC)
│   │   ├── routers/                # tRPC routers
│   │   │   ├── user.router.ts
│   │   │   ├── post.router.ts
│   │   │   └── _app.ts             # Root router
│   │   ├── services/               # Business logic
│   │   │   ├── user.service.ts
│   │   │   └── post.service.ts
│   │   ├── repositories/           # Data access
│   │   │   ├── user.repository.ts
│   │   │   └── post.repository.ts
│   │   ├── middleware/             # tRPC middleware
│   │   │   ├── auth.ts
│   │   │   └── logging.ts
│   │   ├── context.ts              # tRPC context
│   │   └── trpc.ts                 # tRPC setup
│   ├── lib/
│   │   └── trpc/                   # Client tRPC
│   │       ├── client.ts           # tRPC client
│   │       └── Provider.tsx        # tRPC provider
│   └── types/
│       └── index.ts
└── prisma/                         # Database (if using Prisma)
    └── schema.prisma
```

### tRPC Server Setup
```typescript
// server/trpc.ts - tRPC initialization
import { initTRPC, TRPCError } from '@trpc/server';
import { Context } from './context';
import superjson from 'superjson';

const t = initTRPC.context<Context>().create({
  transformer: superjson, // Serializes Date, Map, Set, etc.
});

export const router = t.router;
export const publicProcedure = t.procedure;

// Authenticated middleware
const isAuthed = t.middleware(({ ctx, next }) => {
  if (!ctx.user) {
    throw new TRPCError({ code: 'UNAUTHORIZED' });
  }
  return next({
    ctx: {
      user: ctx.user, // Now TypeScript knows user exists
    },
  });
});

export const protectedProcedure = t.procedure.use(isAuthed);

// Admin middleware
const isAdmin = t.middleware(({ ctx, next }) => {
  if (!ctx.user || ctx.user.role !== 'admin') {
    throw new TRPCError({ code: 'FORBIDDEN' });
  }
  return next({ ctx });
});

export const adminProcedure = t.procedure.use(isAuthed).use(isAdmin);
```
```typescript
// server/context.ts - Create context for each request
import { FetchCreateContextFnOptions } from '@trpc/server/adapters/fetch';
import { verifyJWT } from '@/lib/auth';

export async function createContext({ req }: FetchCreateContextFnOptions) {
  // Get token from header
  const token = req.headers.get('authorization')?.replace('Bearer ', '');
  
  // Verify token and get user
  const user = token ? await verifyJWT(token) : null;
  
  return {
    user,
    // Add services, database clients, etc.
  };
}

export type Context = Awaited<ReturnType<typeof createContext>>;
```
```typescript
// server/routers/user.router.ts - User router
import { router, publicProcedure, protectedProcedure } from '../trpc';
import { z } from 'zod';
import { TRPCError } from '@trpc/server';

export const userRouter = router({
  // Public procedure
  getById: publicProcedure
    .input(z.object({ id: z.string() }))
    .query(async ({ input, ctx }) => {
      const user = await userService.getById(input.id);
      
      if (!user) {
        throw new TRPCError({
          code: 'NOT_FOUND',
          message: 'User not found',
        });
      }
      
      return user;
    }),
  
  // Protected procedure (requires auth)
  getMe: protectedProcedure
    .query(async ({ ctx }) => {
      // ctx.user is guaranteed to exist (TypeScript knows this)
      return userService.getById(ctx.user.id);
    }),
  
  // Mutation
  create: publicProcedure
    .input(z.object({
      name: z.string().min(2).max(100),
      email: z.string().email(),
      password: z.string().min(8),
    }))
    .mutation(async ({ input }) => {
      return userService.create(input);
    }),
  
  // Protected mutation
  update: protectedProcedure
    .input(z.object({
      name: z.string().min(2).max(100).optional(),
      email: z.string().email().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      return userService.update(ctx.user.id, input);
    }),
});
```
```typescript
// server/routers/_app.ts - Root router
import { router } from '../trpc';
import { userRouter } from './user.router';
import { postRouter } from './post.router';

export const appRouter = router({
  user: userRouter,
  post: postRouter,
});

export type AppRouter = typeof appRouter;
```

### tRPC API Route (Next.js App Router)
```typescript
// app/api/trpc/[trpc]/route.ts
import { fetchRequestHandler } from '@trpc/server/adapters/fetch';
import { appRouter } from '@/server/routers/_app';
import { createContext } from '@/server/context';

const handler = (req: Request) =>
  fetchRequestHandler({
    endpoint: '/api/trpc',
    req,
    router: appRouter,
    createContext,
  });

export { handler as GET, handler as POST };
```

### tRPC Client Setup
```typescript
// lib/trpc/client.ts
import { createTRPCClient, httpBatchLink } from '@trpc/client';
import { AppRouter } from '@/server/routers/_app';
import superjson from 'superjson';

function getBaseUrl() {
  if (typeof window !== 'undefined') return '';
  if (process.env.VERCEL_URL) return `https://${process.env.VERCEL_URL}`;
  return `http://localhost:${process.env.PORT ?? 3000}`;
}

export const trpc = createTRPCClient<AppRouter>({
  links: [
    httpBatchLink({
      url: `${getBaseUrl()}/api/trpc`,
      transformer: superjson,
      headers() {
        const token = localStorage.getItem('token');
        return token ? { authorization: `Bearer ${token}` } : {};
      },
    }),
  ],
});
```
```typescript
// lib/trpc/Provider.tsx - React Query wrapper
'use client';

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { httpBatchLink } from '@trpc/client';
import { createTRPCReact } from '@trpc/react-query';
import { useState } from 'react';
import { AppRouter } from '@/server/routers/_app';
import superjson from 'superjson';

export const trpc = createTRPCReact<AppRouter>();

export function TRPCProvider({ children }: { children: React.ReactNode }) {
  const [queryClient] = useState(() => new QueryClient());
  const [trpcClient] = useState(() =>
    trpc.createClient({
      links: [
        httpBatchLink({
          url: '/api/trpc',
          transformer: superjson,
          headers() {
            const token = localStorage.getItem('token');
            return token ? { authorization: `Bearer ${token}` } : {};
          },
        }),
      ],
    })
  );

  return (
    <trpc.Provider client={trpcClient} queryClient={queryClient}>
      <QueryClientProvider client={queryClient}>
        {children}
      </QueryClientProvider>
    </trpc.Provider>
  );
}
```

### Using tRPC in Components
```typescript
// app/(dashboard)/page.tsx
'use client';

import { trpc } from '@/lib/trpc/Provider';

export default function Dashboard() {
  // Query - automatically typed!
  const { data: user, isLoading } = trpc.user.getMe.useQuery();
  
  // Mutation
  const updateUser = trpc.user.update.useMutation({
    onSuccess: () => {
      // Invalidate and refetch
      trpc.useContext().user.getMe.invalidate();
    },
  });
  
  if (isLoading) return <div>Loading...</div>;
  
  return (
    <div>
      <h1>Welcome, {user?.name}</h1>
      <button
        onClick={() => {
          updateUser.mutate({ name: 'New Name' });
        }}
      >
        Update Name
      </button>
    </div>
  );
}
```

### tRPC Best Practices

**96. Use Zod for input validation**: Type-safe runtime validation.

**97. Batch requests**: tRPC batches multiple queries into one HTTP request.

**98. Use React Query features**: Caching, invalidation, optimistic updates.
```typescript
// Optimistic update
const updatePost = trpc.post.update.useMutation({
  onMutate: async (newData) => {
    // Cancel outgoing refetches
    await trpc.useContext().post.getById.cancel({ id: newData.id });
    
    // Snapshot previous value
    const previous = trpc.useContext().post.getById.getData({ id: newData.id });
    
    // Optimistically update
    trpc.useContext().post.getById.setData({ id: newData.id }, (old) => ({
      ...old,
      ...newData,
    }));
    
    return { previous };
  },
  onError: (err, newData, context) => {
    // Rollback on error
    trpc.useContext().post.getById.setData(
      { id: newData.id },
      context?.previous
    );
  },
});
```

**99. Server-side tRPC calls**: Use in server components.
```typescript
// app/(dashboard)/page.tsx - Server Component
import { createCallerFactory } from '@/server/trpc';
import { appRouter } from '@/server/routers/_app';

export default async function DashboardPage() {
  const createCaller = createCallerFactory(appRouter);
  const caller = createCaller({ user: null }); // Pass context
  
  const user = await caller.user.getMe(); // Type-safe server-side call!
  
  return <div>Welcome, {user.name}</div>;
}
```

---

## Serverless API Patterns

### AWS Lambda with API Gateway
```typescript
// handler.ts
import { APIGatewayProxyHandler } from 'aws-lambda';
import { userService } from './services/user.service';

export const getUser: APIGatewayProxyHandler = async (event) => {
  try {
    const userId = event.pathParameters?.id;
    
    if (!userId) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: 'User ID required' }),
      };
    }
    
    const user = await userService.getById(userId);
    
    if (!user) {
      return {
        statusCode: 404,
        body: JSON.stringify({ error: 'User not found' }),
      };
    }
    
    return {
      statusCode: 200,
      body: JSON.stringify({ data: user }),
    };
  } catch (error) {
    console.error(error);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Internal server error' }),
    };
  }
};

export const createUser: APIGatewayProxyHandler = async (event) => {
  try {
    const data = JSON.parse(event.body || '{}');
    const user = await userService.create(data);
    
    return {
      statusCode: 201,
      body: JSON.stringify({ data: user }),
    };
  } catch (error) {
    console.error(error);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Internal server error' }),
    };
  }
};
```
```yaml
# serverless.yml (Serverless Framework)
service: my-api

provider:
  name: aws
  runtime: nodejs18.x
  region: us-east-1
  environment:
    DATABASE_URL: ${env:DATABASE_URL}
    JWT_SECRET: ${env:JWT_SECRET}

functions:
  getUser:
    handler: handler.getUser
    events:
      - httpApi:
          path: /users/{id}
          method: get
  
  createUser:
    handler: handler.createUser
    events:
      - httpApi:
          path: /users
          method: post
```

### Cloudflare Workers
```typescript
// worker.ts
export interface Env {
  DATABASE_URL: string;
  JWT_SECRET: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    
    // Route handling
    if (url.pathname.startsWith('/api/users')) {
      return handleUsers(request, env);
    }
    
    return new Response('Not found', { status: 404 });
  },
};

async function handleUsers(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  
  // GET /api/users/:id
  if (request.method === 'GET') {
    const match = url.pathname.match(/^\/api\/users\/(.+)$/);
    if (match) {
      const userId = match[1];
      const user = await getUserById(userId, env);
      
      if (!user) {
        return Response.json({ error: 'Not found' }, { status: 404 });
      }
      
      return Response.json({ data: user });
    }
  }
  
  // POST /api/users
  if (request.method === 'POST' && url.pathname === '/api/users') {
    const data = await request.json();
    const user = await createUser(data, env);
    return Response.json({ data: user }, { status: 201 });
  }
  
  return Response.json({ error: 'Method not allowed' }, { status: 405 });
}
```

### Vercel Functions (Next.js API Routes)
```typescript
// app/api/users/[id]/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { userService } from '@/services/user.service';

export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const user = await userService.getById(params.id);
    
    if (!user) {
      return NextResponse.json(
        { error: 'User not found' },
        { status: 404 }
      );
    }
    
    return NextResponse.json({ data: user });
  } catch (error) {
    console.error(error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

export async function PATCH(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const data = await request.json();
    const user = await userService.update(params.id, data);
    
    return NextResponse.json({ data: user });
  } catch (error) {
    console.error(error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
```

### Python FastAPI Example
```python
# main.py
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from typing import Optional

app = FastAPI()

class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str

class UserUpdate(BaseModel):
    name: Optional[str] = None
    email: Optional[EmailStr] = None

class User(BaseModel):
    id: str
    name: str
    email: str
    
    class Config:
        orm_mode = True

@app.get("/users/{user_id}", response_model=User)
async def get_user(user_id: str):
    user = await user_service.get_by_id(user_id)
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return user

@app.post("/users", response_model=User, status_code=201)
async def create_user(user_data: UserCreate):
    return await user_service.create(user_data)

@app.patch("/users/{user_id}", response_model=User)
async def update_user(user_id: str, user_data: UserUpdate):
    user = await user_service.update(user_id, user_data)
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return user

# Run with: uvicorn main:app --reload
```

