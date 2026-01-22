# Cursor AI Development Rules - Scalable & Cost-Efficient Architecture

This guide helps you structure code and choose deployment strategies that:
- Scale automatically based on demand
- Keep costs low when usage is low
- Scale costs proportionally with revenue (user purchases)
- Are deployment-agnostic (work on Vercel, AWS, GCP, Azure, etc.)

## Core Principles

### 1. **Pay-per-Use Architecture**

Structure your application so you only pay for what you use:
- Serverless functions (pay per invocation, not idle time)
- Managed databases with auto-scaling (pay for storage + queries)
- CDN for static assets (pay for bandwidth used)
- Object storage for files (pay for storage + bandwidth)

### 2. **Revenue-Aligned Scaling**

Design so costs increase only when revenue increases:
- Free tier users → minimal infrastructure costs
- Paying users → their subscription covers increased costs
- High-usage features → gated behind payment
- Background jobs → only run when needed (user actions trigger them)

### 3. **Separation of Concerns for Scaling**

Separate components that scale differently:
- **Static assets** → CDN (Cloudflare, Vercel Edge)
- **API/Backend** → Serverless or containerized auto-scaling
- **Database** → Managed database with connection pooling
- **File storage** → Object storage (S3, R2, GCS)
- **Background jobs** → Queue-based workers (only run when needed)
- **Real-time features** → Separate WebSocket service (scales independently)

## Architecture Patterns

### Pattern 1: Serverless-First (Best for Most Apps)

**When to use:**
- Starting out (low costs when idle)
- Unpredictable traffic patterns
- Want minimal ops overhead
- Traffic can tolerate cold starts (100-500ms)

**Architecture:**
```
┌─────────────────────────────────────────────────┐
│                    CDN/Edge                      │
│         (Cloudflare, Vercel, CloudFront)         │
│         Static Assets + Edge Functions            │
└──────────────────┬──────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────┐
│              Serverless Functions                │
│        (Vercel Functions, AWS Lambda,            │
│         Cloudflare Workers, Azure Functions)     │
│                                                  │
│  - API routes                                    │
│  - Authentication                                │
│  - Business logic                                │
│  - Only charged when invoked                     │
└──────────────────┬──────────────────────────────┘
                   │
    ┌──────────────┼──────────────┐
    │              │              │
┌───▼────┐  ┌──────▼──────┐  ┌───▼──────┐
│Database│  │ Object      │  │ Queue    │
│(Managed│  │ Storage     │  │ (Redis,  │
│Postgres│  │ (S3, R2)    │  │ SQS)     │
│Supabase│  │             │  │          │
│PlanetSc│  │ - User      │  │ - Email  │
│Neon)   │  │   uploads   │  │ - Jobs   │
└────────┘  └─────────────┘  └──────────┘
```

**Project Structure:**
```
my-app/
├── apps/
│   ├── web/                        # Frontend (Next.js)
│   │   ├── app/
│   │   │   ├── (auth)/            # Auth pages
│   │   │   ├── (dashboard)/       # Protected pages
│   │   │   ├── api/               # API routes (serverless)
│   │   │   │   ├── auth/
│   │   │   │   ├── users/
│   │   │   │   └── webhooks/
│   │   │   └── layout.tsx
│   │   └── public/
│   └── extension/                  # Chrome extension (if applicable)
├── packages/
│   ├── database/                   # Database schema & migrations
│   │   ├── prisma/
│   │   │   └── schema.prisma
│   │   └── migrations/
│   ├── shared/                     # Shared types, utils
│   │   ├── types/
│   │   ├── utils/
│   │   └── constants/
│   ├── api-client/                 # API client (for extension)
│   └── ui/                         # Shared UI components
├── services/                       # Separate scalable services
│   ├── email/                      # Email service (optional worker)
│   └── webhooks/                   # Webhook processor
└── infrastructure/                 # IaC (if needed)
    └── terraform/
```

**Cost Structure:**
- **Free tier**: Static hosting + minimal API calls = $0-5/month
- **Low usage** (<1000 users): $20-50/month
- **Medium usage** (10K users): $100-300/month
- **High usage** (100K+ users): $1000+/month (but revenue should be $10K+)

**Deployment Options:**
- **Vercel** (easiest, great DX, generous free tier)
- **Netlify** (similar to Vercel)
- **Cloudflare Pages + Workers** (cheapest at scale)
- **AWS Lambda + API Gateway** (most flexible, more complex)

---

### Pattern 2: Hybrid (Serverless + Long-Running Services)

**When to use:**
- Some features need always-on services (WebSockets, background jobs)
- Serverless for API, containers for stateful services
- Moderate to high traffic
- Need predictable performance (no cold starts)

**Architecture:**
```
┌────────────────────────────────────────────────┐
│                  CDN/Edge                       │
└──────────────────┬─────────────────────────────┘
                   │
    ┌──────────────┼──────────────┐
    │              │              │
┌───▼──────────┐ ┌─▼──────────┐ ┌▼────────────┐
│ Serverless   │ │ Container  │ │ Container   │
│ Functions    │ │ (API)      │ │ (WebSocket) │
│              │ │            │ │             │
│ - Auth       │ │ - CRUD     │ │ - Real-time │
│ - Webhooks   │ │ - Complex  │ │ - Chat      │
│ - Triggers   │ │   queries  │ │ - Notifs    │
└──────────────┘ └────────────┘ └─────────────┘
                   │              │
    ┌──────────────┼──────────────┼──────────┐
    │              │              │          │
┌───▼─────┐  ┌────▼────┐  ┌──────▼──┐  ┌───▼────┐
│Database │  │ Redis   │  │ Queue   │  │ Storage│
└─────────┘  └─────────┘  └─────────┘  └────────┘
```

**When to use containers vs serverless:**

| Feature | Use Serverless | Use Container |
|---------|---------------|---------------|
| HTTP API (CRUD) | ✅ Best choice | ❌ Overkill |
| Webhooks | ✅ Perfect | ❌ Overkill |
| Background jobs | ✅ With queue | ✅ Worker service |
| WebSockets | ❌ Expensive | ✅ Long-running |
| Complex queries | ✅ If <30s | ✅ If >30s |
| Real-time | ❌ Not ideal | ✅ Persistent connections |

**Cost Structure:**
- Small container (256MB): ~$5-10/month
- Medium container (512MB): ~$15-20/month
- Large container (1GB): ~$30-40/month
- Plus serverless costs for API

---

### Pattern 3: Multi-Tenant SaaS

**When to use:**
- Building a SaaS product
- Multiple customers (tenants) sharing infrastructure
- Need to isolate tenant data
- Want to scale per-tenant

**Architecture:**
```
┌────────────────────────────────────────────────┐
│              Load Balancer / CDN                │
└──────────────────┬─────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────┐
│            API Gateway / Router                  │
│         (Identifies tenant from request)         │
└──────────────────┬──────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────┐
│              Application Layer                   │
│         (Shared or tenant-specific)              │
└──────────────────┬──────────────────────────────┘
                   │
    ┌──────────────┴──────────────┐
    │                             │
┌───▼──────────────┐  ┌───────────▼──────────┐
│ Shared Database  │  │ Per-Tenant Database  │
│                  │  │                      │
│ - All tenants    │  │ - Tenant A           │
│   in one DB      │  │ - Tenant B           │
│ - Row-level      │  │ - Tenant C           │
│   tenant_id      │  │                      │
│                  │  │ - Better isolation   │
│ - Cheaper        │  │ - Higher cost        │
└──────────────────┘  └──────────────────────┘
```

**Project Structure:**
```
my-saas/
├── apps/
│   ├── web/                        # Customer-facing app
│   ├── admin/                      # Admin dashboard
│   └── api/                        # API
│       ├── src/
│       │   ├── middleware/
│       │   │   ├── tenant.ts      # Tenant identification
│       │   │   └── auth.ts
│       │   ├── modules/
│       │   │   ├── tenants/       # Tenant management
│       │   │   ├── users/
│       │   │   └── billing/       # Subscription management
│       │   └── database/
│       │       ├── tenant-context.ts  # Tenant-scoped queries
│       │       └── migrations/
└── packages/
    └── multi-tenant/              # Shared multi-tenant logic
        ├── tenant-resolver.ts
        ├── tenant-context.ts
        └── rbac.ts               # Role-based access control
```

**Tenant Identification:**
```typescript
// middleware/tenant.ts
export async function identifyTenant(req: Request): Promise<Tenant> {
  // Method 1: Subdomain (tenant1.myapp.com)
  const subdomain = req.headers.get('host')?.split('.')[0];
  if (subdomain && subdomain !== 'www') {
    return await tenantService.getBySubdomain(subdomain);
  }
  
  // Method 2: Custom domain (customer.com → tenant)
  const customDomain = req.headers.get('host');
  const tenant = await tenantService.getByDomain(customDomain);
  if (tenant) return tenant;
  
  // Method 3: Header (for APIs)
  const tenantId = req.headers.get('x-tenant-id');
  if (tenantId) {
    return await tenantService.getById(tenantId);
  }
  
  throw new Error('Tenant not identified');
}

// Tenant-scoped database queries
export class TenantScopedRepository {
  constructor(private tenantId: string) {}
  
  async getUsers() {
    return db.user.findMany({
      where: { tenantId: this.tenantId }
    });
  }
  
  async createUser(data: CreateUserDto) {
    return db.user.create({
      data: {
        ...data,
        tenantId: this.tenantId, // Always include tenant
      }
    });
  }
}
```

**Billing Integration:**
```typescript
// modules/billing/billing.service.ts
export class BillingService {
  async handleSubscriptionCreated(event: StripeEvent) {
    const subscription = event.data.object;
    
    // Update tenant
    await tenantService.update(subscription.metadata.tenantId, {
      subscriptionId: subscription.id,
      plan: subscription.items.data[0].price.id,
      status: 'active',
    });
    
    // Upgrade features
    await featureService.enable(subscription.metadata.tenantId, {
      maxUsers: 50,
      apiLimit: 10000,
    });
  }
  
  async handleSubscriptionDeleted(event: StripeEvent) {
    const subscription = event.data.object;
    
    // Downgrade to free tier
    await tenantService.update(subscription.metadata.tenantId, {
      status: 'inactive',
      plan: 'free',
    });
    
    await featureService.downgrade(subscription.metadata.tenantId);
  }
}
```

---

## Database Strategy for Cost Efficiency

### Managed Database Options (Ranked by Cost)

1. **Supabase** (Postgres)
   - Free tier: 500MB, 2GB bandwidth
   - Pro: $25/month (8GB)
   - Auto-pauses on inactivity (free tier)
   - Built-in auth, storage, realtime

2. **Neon** (Serverless Postgres)
   - Free tier: 0.5GB, auto-suspend
   - Scale to zero (pay only for active time)
   - Branch database for each PR
   - $19/month for production

3. **PlanetScale** (MySQL)
   - Free tier: 5GB storage, 1 billion row reads/month
   - Scaler: $39/month
   - Branching for safe schema changes
   - No downtime migrations

4. **MongoDB Atlas** (NoSQL)
   - Free tier: 512MB
   - Serverless: pay per operation
   - $9/month for dedicated cluster

5. **AWS RDS / Google Cloud SQL** (Traditional)
   - No free tier
   - Always-on (expensive at low usage)
   - $15-30/month minimum
   - Use for: >1M requests/day

### Connection Pooling (Critical for Serverless)

Serverless functions create many connections. Use connection pooling:
```typescript
// ❌ BAD - New connection per function invocation
import { Pool } from 'pg';

export async function handler() {
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  const result = await pool.query('SELECT * FROM users');
  await pool.end(); // Closes connection (wasteful)
  return result.rows;
}

// ✅ GOOD - Pooler like PgBouncer or Supabase Pooler
import { Pool } from 'pg';

// Reused across invocations
const pool = new Pool({
  connectionString: process.env.DATABASE_POOL_URL, // Pooler URL
  max: 1, // Limit connections per function
});

export async function handler() {
  const result = await pool.query('SELECT * FROM users');
  return result.rows;
}

// ✅ EVEN BETTER - Prisma Data Proxy or Neon Serverless Driver
import { PrismaClient } from '@prisma/client/edge';

const prisma = new PrismaClient({
  datasources: {
    db: {
      url: process.env.DATABASE_URL, // Uses Prisma Data Proxy
    },
  },
});

export async function handler() {
  const users = await prisma.user.findMany();
  return users;
}
```

**Connection Pooling Options:**
- **Supabase Pooler** (built-in, use `[supabase-url]:6543` port)
- **Neon** (built-in serverless driver, no pooler needed)
- **PlanetScale** (built-in, no pooler needed)
- **PgBouncer** (self-hosted or managed)
- **Prisma Data Proxy** ($25/month, handles connections)

---

## File Storage Strategy

### Object Storage Options

**Don't store files in database.** Use object storage:

1. **Cloudflare R2** (Best value)
   - $0.015/GB/month (storage)
   - No egress fees (free bandwidth!)
   - S3-compatible API
   - Best for: Public files, CDN

2. **Vercel Blob** (Easiest for Next.js)
   - $0.15/GB/month (storage)
   - $0.10/GB (bandwidth)
   - Integrated with Vercel
   - Best for: Vercel-deployed apps

3. **AWS S3**
   - $0.023/GB/month (storage)
   - $0.09/GB (bandwidth)
   - Industry standard
   - Best for: AWS ecosystem

4. **Supabase Storage**
   - Free tier: 1GB
   - $0.021/GB/month
   - Built into Supabase
   - Best for: Using Supabase

**File Upload Pattern:**
```typescript
// API route: Generate presigned URL
export async function POST(req: Request) {
  const { filename, contentType } = await req.json();
  
  // Generate presigned URL (user uploads directly to storage)
  const presignedUrl = await storage.generatePresignedUrl({
    bucket: 'user-uploads',
    key: `${userId}/${uuid()}/${filename}`,
    contentType,
    expiresIn: 3600, // 1 hour
  });
  
  return Response.json({ uploadUrl: presignedUrl });
}

// Client uploads directly to storage (bypasses API)
async function uploadFile(file: File) {
  const { uploadUrl } = await fetch('/api/upload-url', {
    method: 'POST',
    body: JSON.stringify({
      filename: file.name,
      contentType: file.type,
    }),
  }).then(r => r.json());
  
  // Upload directly to storage
  await fetch(uploadUrl, {
    method: 'PUT',
    body: file,
    headers: { 'Content-Type': file.type },
  });
}
```

**Why this pattern?**
- Files don't go through your API (saves bandwidth costs)
- Scales infinitely (storage handles it)
- Faster for users (direct upload)

---

## Background Jobs & Queues

### When You Need Background Processing

- Sending emails (don't block HTTP response)
- Processing images/videos
- Generating reports
- Webhooks (retry on failure)
- Scheduled tasks (cleanup, reminders)

### Queue Options (Pay-per-Use)

1. **Vercel Cron Jobs** (Free, simple)
   - Scheduled functions (cron syntax)
   - Limited to Vercel-deployed functions
   - Best for: Simple scheduled tasks
```typescript
// app/api/cron/cleanup/route.ts
export async function GET(req: Request) {
  // Verify cron secret
  if (req.headers.get('authorization') !== `Bearer ${process.env.CRON_SECRET}`) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }
  
  // Run cleanup
  await cleanupOldData();
  
  return Response.json({ success: true });
}

// vercel.json
{
  "crons": [
    {
      "path": "/api/cron/cleanup",
      "schedule": "0 0 * * *"  // Daily at midnight
    }
  ]
}
```

2. **Upstash (Redis-based queue)**
   - Pay-per-request pricing
   - $0.2 per 100K requests
   - Free tier: 10K requests/day
   - Best for: Event-driven jobs
```typescript
import { Queue } from '@upstash/qstash';

const queue = new Queue({
  token: process.env.QSTASH_TOKEN!,
  url: process.env.QSTASH_URL!,
});

// Enqueue job
await queue.publish({
  url: 'https://myapp.com/api/jobs/send-email',
  body: { userId: '123', template: 'welcome' },
});

// Process job (API route)
export async function POST(req: Request) {
  const { userId, template } = await req.json();
  await sendEmail(userId, template);
  return Response.json({ success: true });
}
```

3. **AWS SQS** (Most mature)
   - $0.40 per 1M requests
   - Free tier: 1M requests/month
   - Requires worker to poll queue
   - Best for: AWS ecosystem, high volume

4. **BullMQ + Redis**
   - Self-hosted queue
   - Requires Redis instance
   - Best for: Complex job scheduling, retries

### Decision Tree for Background Jobs
```
Simple scheduled task (daily cleanup)? → Vercel Cron
Triggered by user action (send email after signup)? → Upstash QStash
High volume (>1M jobs/month)? → AWS SQS or BullMQ
Need complex retries, priorities? → BullMQ
```

---

## Scaling Decision Framework

### Stage 1: MVP (0-1000 users)

**Goal:** Build fast, keep costs near $0

**Architecture:**
- Vercel (frontend + API routes)
- Supabase Free Tier (database + auth + storage)
- No separate services yet
- No CDN needed (Vercel handles it)

**Monthly Cost:** $0-10

**Code Structure:**
```
my-app/
├── app/
│   ├── (auth)/
│   ├── (dashboard)/
│   └── api/
└── lib/
    └── supabase.ts
```

---

### Stage 2: Early Traction (1K-10K users)

**Goal:** Maintain velocity, start charging

**Architecture:**
- Vercel or Cloudflare Pages (frontend)
- Vercel Functions or Cloudflare Workers (API)
- Supabase Pro or Neon (database)
- Cloudflare R2 (file storage)
- Stripe (payments)

**Monthly Cost:** $30-100

**New additions:**
- Background jobs (Upstash or Vercel Cron)
- Monitoring (Sentry, LogRocket)
- Email (Resend, SendGrid free tier)

---

### Stage 3: Growing (10K-100K users)

**Goal:** Optimize costs, improve performance

**Architecture:**
- Split frontend and backend (if needed)
- Consider containers for heavy workloads
- Add caching (Cloudflare Cache, Vercel Edge Config)
- Separate WebSocket service (if real-time features)

**Monthly Cost:** $200-1000

**Optimizations:**
- Database: Tune queries, add indexes
- Caching: Redis for sessions, computed data
- CDN: Aggressive caching for static content
- Monitoring: Detailed metrics, alerting

---

### Stage 4: Scale (100K+ users)

**Goal:** Maintain performance, predictable costs

**Architecture:**
- Multi-region (if global users)
- Read replicas (database)
- Separate services by domain
- Consider microservices (if team >10 people)

**Monthly Cost:** $1000-10000+ (but revenue should be $50K+)

---

## Cost Optimization Checklist

### ✅ Always Do This

1. **Use serverless for APIs** (unless >100K requests/day)
2. **Use CDN for static assets** (Cloudflare, Vercel Edge)
3. **Use object storage for files** (not database)
4. **Use connection pooling** for database
5. **Compress responses** (gzip/brotli)
6. **Cache aggressively** (browser cache, CDN cache, API cache)
7. **Lazy load images** (Next.js Image, Cloudinary)
8. **Monitor costs** (set up billing alerts)

### ❌ Don't Do This (Until You Need It)

1. **Don't use always-on containers** (until >100K requests/day)
2. **Don't use Kubernetes** (until team >20 people, >1M users)
3. **Don't build your own auth** (use Auth0, Supabase, Clerk)
4. **Don't run your own database** (use managed)
5. **Don't premature optimize** (measure first)
6. **Don't use microservices** (until monolith is truly a problem)

---

## Revenue-Aligned Feature Gating

Structure features so heavy usage requires payment:
```typescript
// Check usage limits
export async function checkUsageLimit(userId: string, feature: string) {
  const user = await userService.getById(userId);
  const usage = await usageService.getUsage(userId, feature);
  
  // Free tier limits
  if (user.plan === 'free') {
    if (feature === 'api_calls' && usage.count >= 1000) {
      throw new Error('API limit reached. Upgrade to continue.');
    }
    if (feature === 'storage' && usage.bytes >= 100 * 1024 * 1024) { // 100MB
      throw new Error('Storage limit reached. Upgrade to continue.');
    }
  }
  
  // Pro tier limits
  if (user.plan === 'pro') {
    if (feature === 'api_calls' && usage.count >= 100000) {
      throw new Error('API limit reached. Contact sales.');
    }
  }
  
  // Track usage
  await usageService.increment(userId, feature);
}

// Use in API routes
export async function POST(req: Request) {
  const userId = req.user.id;
  
  // Check limit before expensive operation
  await checkUsageLimit(userId, 'api_calls');
  
  // Process request
  const result = await heavyComputation();
  return Response.json(result);
}
```

**Feature Tiers Example:**

| Feature | Free | Pro ($29/mo) | Enterprise |
|---------|------|--------------|------------|
| API Calls | 1,000/mo | 100,000/mo | Unlimited |
| Storage | 100MB | 10GB | Unlimited |
| Team Members | 1 | 10 | Unlimited |
| Support | Email | Priority | Dedicated |

---

## Deployment-Agnostic Code Structure

Write code that works on any platform:
```typescript
// ❌ BAD - Platform-specific
import { NextRequest, NextResponse } from 'next/server';

export function handler(req: NextRequest) {
  return NextResponse.json({ data: 'hello' });
}

// ✅ GOOD - Platform-agnostic
export async function handler(req: Request): Promise<Response> {
  return Response.json({ data: 'hello' });
}

// Works on:
// - Vercel Functions
// - Cloudflare Workers  
// - AWS Lambda (with adapter)
// - Google Cloud Functions (with adapter)
```

**Adapter Pattern for Platform Differences:**
```typescript
// adapters/request.adapter.ts
export interface AdaptedRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: any;
}

export function adaptRequest(req: any): AdaptedRequest {
  // Detect platform
  if ('nextUrl' in req) {
    // Vercel/Next.js
    return {
      method: req.method,
      url: req.nextUrl.toString(),
      headers: Object.fromEntries(req.headers),
      body: req.json(),
    };
  }
  
  if ('cf' in req) {
    // Cloudflare Workers
    return {
      method: req.method,
      url: req.url,
      headers: Object.fromEntries(req.headers),
      body: req.json(),
    };
  }
  
  // Standard Request
  return {
    method: req.method,
    url: req.url,
    headers: Object.fromEntries(req.headers),
    body: req.json(),
  };
}
```

---

## Summary: Cost-Efficient Scalability Rules

1. **Start serverless** - Pay only for what you use
2. **Use managed databases** - They scale automatically
3. **Object storage for files** - Don't bloat your database
4. **Connection pooling** - Critical for serverless + database
5. **CDN everything static** - Save bandwidth costs
6. **Background jobs only when needed** - Use queues, not always-on workers
7. **Feature gate heavy usage** - Free tier has limits, paid tier scales
8. **Monitor costs early** - Set billing alerts
9. **Platform-agnostic code** - Easy to switch if needed
10. **Scale vertically first** - Upgrade database before adding services

**Golden Rule:** Your infrastructure costs should be 10-20% of revenue. If costs are 50%+, you're over-engineering or under-charging.