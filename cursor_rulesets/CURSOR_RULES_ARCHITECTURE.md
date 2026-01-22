Cursor AI Development Rules - Project Architecture & Modular Design

These rules cover project organization, file structure, modular design patterns, and architectural best practices.

## Core Architectural Principles

1. **Separation of Concerns**: Different parts of the application should handle different responsibilities. Business logic separate from UI, data access separate from business logic, configuration separate from code.

2. **High Cohesion, Loose Coupling**: Keep related code together (high cohesion). Minimize dependencies between modules (loose coupling).

3. **Single Responsibility Principle (SRP)**: Each module, class, or function should have one reason to change. If you can describe it with "and" or "or", it's doing too much.

4. **Don't Repeat Yourself (DRY)**: Extract common patterns. If code appears 3+ times, it should be abstracted into a reusable module.

5. **You Aren't Gonna Need It (YAGNI)**: Don't build features or abstractions until you actually need them. Avoid speculative generalization.

6. **Keep It Simple, Stupid (KISS)**: Prefer simple solutions. Complexity should be justified by real requirements, not hypothetical future needs.

## Project Structure by Type

### React/Next.js Project Structure
```
my-app/
├── public/                      # Static assets
│   ├── images/
│   ├── fonts/
│   └── favicon.ico
├── src/
│   ├── app/                     # Next.js App Router (or pages/ for Pages Router)
│   │   ├── (auth)/             # Route groups
│   │   │   ├── login/
│   │   │   └── register/
│   │   ├── dashboard/
│   │   ├── api/                # API routes
│   │   ├── layout.tsx
│   │   ├── page.tsx
│   │   └── error.tsx
│   ├── components/             # Reusable UI components
│   │   ├── ui/                 # Generic UI components (buttons, inputs, cards)
│   │   │   ├── button.tsx
│   │   │   ├── input.tsx
│   │   │   └── card.tsx
│   │   ├── forms/              # Form-specific components
│   │   │   ├── login-form.tsx
│   │   │   └── user-form.tsx
│   │   └── layout/             # Layout components (header, footer, sidebar)
│   │       ├── header.tsx
│   │       ├── footer.tsx
│   │       └── sidebar.tsx
│   ├── features/               # Feature-based modules (domain-driven)
│   │   ├── auth/
│   │   │   ├── components/    # Feature-specific components
│   │   │   ├── hooks/         # Feature-specific hooks
│   │   │   ├── services/      # API calls, business logic
│   │   │   ├── types/         # TypeScript types
│   │   │   ├── utils/         # Feature-specific utilities
│   │   │   └── index.ts       # Public API of the feature
│   │   ├── users/
│   │   │   ├── components/
│   │   │   ├── hooks/
│   │   │   ├── services/
│   │   │   ├── types/
│   │   │   └── index.ts
│   │   └── dashboard/
│   ├── lib/                    # Third-party library configurations
│   │   ├── api-client.ts      # Axios/fetch configuration
│   │   ├── auth.ts            # Auth library setup
│   │   └── database.ts        # Database client setup
│   ├── hooks/                  # Shared custom hooks
│   │   ├── use-auth.ts
│   │   ├── use-local-storage.ts
│   │   └── use-media-query.ts
│   ├── services/               # Shared API services
│   │   ├── api.ts             # Base API service
│   │   ├── auth-service.ts
│   │   └── user-service.ts
│   ├── types/                  # Shared TypeScript types
│   │   ├── index.ts
│   │   ├── api.ts
│   │   └── models.ts
│   ├── utils/                  # Shared utility functions
│   │   ├── format.ts
│   │   ├── validation.ts
│   │   └── date.ts
│   ├── constants/              # Shared constants
│   │   ├── routes.ts
│   │   ├── api-endpoints.ts
│   │   └── config.ts
│   ├── store/                  # State management (if using Redux/Zustand)
│   │   ├── slices/
│   │   ├── store.ts
│   │   └── hooks.ts
│   ├── styles/                 # Global styles
│   │   └── globals.css
│   └── middleware.ts           # Next.js middleware
├── tests/                      # Test files (mirror src structure)
│   ├── unit/
│   ├── integration/
│   └── e2e/
├── .env.example
├── .env.local
├── .gitignore
├── next.config.js
├── tailwind.config.js
├── tsconfig.json
├── package.json
├── README.md
└── CHANGES.md
```

### Node.js/Express API Project Structure
```
my-api/
├── src/
│   ├── modules/                # Feature modules (domain-driven)
│   │   ├── users/
│   │   │   ├── users.controller.ts   # HTTP handlers
│   │   │   ├── users.service.ts      # Business logic
│   │   │   ├── users.repository.ts   # Data access
│   │   │   ├── users.model.ts        # Database model/schema
│   │   │   ├── users.routes.ts       # Route definitions
│   │   │   ├── users.validators.ts   # Input validation
│   │   │   ├── users.types.ts        # TypeScript types
│   │   │   └── index.ts              # Module exports
│   │   ├── auth/
│   │   │   ├── auth.controller.ts
│   │   │   ├── auth.service.ts
│   │   │   ├── auth.middleware.ts
│   │   │   ├── auth.routes.ts
│   │   │   └── index.ts
│   │   └── products/
│   ├── shared/                 # Shared across modules
│   │   ├── middleware/
│   │   │   ├── error-handler.ts
│   │   │   ├── auth.ts
│   │   │   ├── validation.ts
│   │   │   └── rate-limit.ts
│   │   ├── utils/
│   │   │   ├── logger.ts
│   │   │   ├── validation.ts
│   │   │   └── crypto.ts
│   │   ├── types/
│   │   │   ├── express.d.ts   # Express type extensions
│   │   │   └── common.ts
│   │   └── constants/
│   │       ├── errors.ts
│   │       └── config.ts
│   ├── config/                 # Configuration
│   │   ├── database.ts
│   │   ├── redis.ts
│   │   ├── env.ts             # Environment variable validation
│   │   └── index.ts
│   ├── database/               # Database-related
│   │   ├── migrations/
│   │   ├── seeds/
│   │   └── connection.ts
│   ├── app.ts                  # Express app setup
│   └── server.ts               # Server entry point
├── tests/
│   ├── unit/
│   ├── integration/
│   └── e2e/
├── .env.example
├── .env
├── .gitignore
├── tsconfig.json
├── package.json
├── README.md
└── CHANGES.md
```

### Python/Data Science Project Structure
```
my-project/
├── data/                       # Data directory (gitignored)
│   ├── raw/                    # Original, immutable data
│   ├── processed/              # Cleaned, transformed data
│   ├── interim/                # Intermediate data
│   └── external/               # Third-party data
├── notebooks/                  # Jupyter notebooks
│   ├── 01_exploration.ipynb
│   ├── 02_preprocessing.ipynb
│   └── 03_modeling.ipynb
├── src/
│   ├── data/                   # Data loading and preprocessing
│   │   ├── __init__.py
│   │   ├── load.py
│   │   ├── clean.py
│   │   └── transform.py
│   ├── features/               # Feature engineering
│   │   ├── __init__.py
│   │   ├── build_features.py
│   │   └── select_features.py
│   ├── models/                 # Model definitions and training
│   │   ├── __init__.py
│   │   ├── train.py
│   │   ├── predict.py
│   │   └── evaluate.py
│   ├── visualization/          # Plotting and visualization
│   │   ├── __init__.py
│   │   └── plot.py
│   ├── utils/                  # Utility functions
│   │   ├── __init__.py
│   │   ├── config.py
│   │   └── helpers.py
│   └── __init__.py
├── models/                     # Saved model artifacts (gitignored)
│   └── .gitkeep
├── reports/                    # Generated reports, figures
│   └── figures/
├── tests/
│   ├── test_data/
│   ├── test_features/
│   └── test_models/
├── config/                     # Configuration files
│   ├── config.yaml
│   └── logging.yaml
├── .env.example
├── .gitignore
├── requirements.txt
├── setup.py
├── README.md
└── CHANGES.md
```

## Modular Design Patterns

### 7. Feature-Based Organization (Recommended for Most Projects)

Group by feature/domain, not by technical type. Each feature is self-contained.

**Good (Feature-based):**
```
features/
  users/
    components/
    hooks/
    services/
    types/
  products/
    components/
    hooks/
    services/
    types/
```

**Less Good (Type-based):**
```
components/
  UserList.tsx
  UserCard.tsx
  ProductList.tsx
  ProductCard.tsx
hooks/
  useUser.ts
  useProduct.ts
services/
  userService.ts
  productService.ts
```

**Why**: Feature-based organization makes it easier to:
- Find all code related to a feature
- Delete or refactor features without touching other code
- Split into microservices later
- Onboard new developers (they can focus on one feature)

### 8. Module Public API Pattern

Each module should export a clear public API via index.ts. Internal implementation details stay private.
```typescript
// features/users/index.ts - PUBLIC API
export { UserList, UserCard } from './components';
export { useUsers, useUserById } from './hooks';
export { userService } from './services';
export type { User, UserFilters } from './types';

// Don't export internal utilities, helpers, or implementation details
// Users of this module only see what's in index.ts
```

**Benefits:**
- Clear API boundaries
- Easy to refactor internals without breaking consumers
- Prevents tight coupling
- Self-documenting (index.ts shows what's available)

### 9. Layered Architecture Pattern

Separate code into layers with clear dependencies: Presentation → Business Logic → Data Access
```
┌─────────────────────┐
│   Presentation      │  ← Components, Controllers (UI/API)
│   (Components)      │
└──────────┬──────────┘
           │
           ↓
┌─────────────────────┐
│   Business Logic    │  ← Services, Use Cases
│   (Services)        │
└──────────┬──────────┘
           │
           ↓
┌─────────────────────┐
│   Data Access       │  ← Repositories, API clients
│   (Repositories)    │
└──────────┬──────────┘
           │
           ↓
┌─────────────────────┐
│   Database/API      │  ← External systems
└─────────────────────┘
```

**Rules:**
- Upper layers can depend on lower layers
- Lower layers CANNOT depend on upper layers
- Each layer has a specific responsibility

**Example:**
```typescript
// ❌ BAD - Repository depends on React component
export class UserRepository {
  async getUsers() {
    // ... fetch data
    return ; // NO! Repository shouldn't know about UI
  }
}

// ✅ GOOD - Clear separation
// Repository (Data Access Layer)
export class UserRepository {
  async getUsers(): Promise {
    return fetch('/api/users').then(r => r.json());
  }
}

// Service (Business Logic Layer)
export class UserService {
  constructor(private repo: UserRepository) {}
  
  async getActiveUsers(): Promise {
    const users = await this.repo.getUsers();
    return users.filter(u => u.isActive);
  }
}

// Component (Presentation Layer)
export function UserList() {
  const users = useQuery(() => userService.getActiveUsers());
  return {users.map(u => )};
}
```

### 10. Dependency Injection Pattern

Pass dependencies as parameters rather than importing them directly. Makes code testable and flexible.
```typescript
// ❌ BAD - Hard-coded dependency
import { apiClient } from '@/lib/api-client';

export class UserService {
  async getUsers() {
    return apiClient.get('/users'); // Can't test without real API
  }
}

// ✅ GOOD - Dependency injection
export class UserService {
  constructor(private apiClient: ApiClient) {}
  
  async getUsers() {
    return this.apiClient.get('/users'); // Can inject mock for testing
  }
}

// Usage
const userService = new UserService(apiClient);

// Testing
const mockApiClient = { get: jest.fn() };
const userService = new UserService(mockApiClient);
```

### 11. Composition Over Inheritance

Prefer composing small pieces over deep inheritance hierarchies.
```typescript
// ❌ BAD - Deep inheritance
class Animal {}
class Mammal extends Animal {}
class Dog extends Mammal {}
class Labrador extends Dog {} // Too deep, inflexible

// ✅ GOOD - Composition
interface CanBark {
  bark(): void;
}

interface CanFetch {
  fetch(item: string): void;
}

class Labrador implements CanBark, CanFetch {
  bark() { console.log('Woof!'); }
  fetch(item: string) { console.log(`Fetching ${item}`); }
}
```

### 12. Factory Pattern for Complex Object Creation

Use factories when object creation is complex or depends on configuration.
```typescript
// ❌ BAD - Complex creation logic scattered
const prodApiClient = new ApiClient(PROD_URL, prodAuth, prodHeaders);
const devApiClient = new ApiClient(DEV_URL, devAuth, devHeaders);

// ✅ GOOD - Factory centralizes creation
export class ApiClientFactory {
  static create(env: 'production' | 'development'): ApiClient {
    if (env === 'production') {
      return new ApiClient({
        baseURL: PROD_URL,
        auth: prodAuth,
        headers: prodHeaders,
      });
    }
    return new ApiClient({
      baseURL: DEV_URL,
      auth: devAuth,
      headers: devHeaders,
    });
  }
}

const apiClient = ApiClientFactory.create(process.env.NODE_ENV);
```

### 13. Repository Pattern for Data Access

Abstract data access behind repositories. Business logic doesn't care if data comes from REST API, GraphQL, database, or localStorage.
```typescript
// Define interface
export interface UserRepository {
  getById(id: string): Promise;
  getAll(): Promise;
  create(user: CreateUserDto): Promise;
  update(id: string, user: UpdateUserDto): Promise;
  delete(id: string): Promise;
}

// Implementation for REST API
export class ApiUserRepository implements UserRepository {
  async getById(id: string): Promise {
    return apiClient.get(`/users/${id}`);
  }
  // ... other methods
}

// Implementation for localStorage (for offline mode)
export class LocalStorageUserRepository implements UserRepository {
  async getById(id: string): Promise {
    const users = JSON.parse(localStorage.getItem('users') || '[]');
    return users.find(u => u.id === id);
  }
  // ... other methods
}

// Business logic doesn't care which implementation
export class UserService {
  constructor(private userRepo: UserRepository) {} // Could be either!
  
  async getUser(id: string) {
    return this.userRepo.getById(id);
  }
}
```

### 14. Service Layer Pattern

Put business logic in services, not in components or controllers.
```typescript
// ❌ BAD - Business logic in component
export function UserProfile({ userId }: { userId: string }) {
  const [user, setUser] = useState(null);
  
  useEffect(() => {
    // Business logic mixed with UI logic
    fetch(`/api/users/${userId}`)
      .then(r => r.json())
      .then(user => {
        if (user.age < 18) {
          user.canVote = false;
        } else {
          user.canVote = true;
        }
        setUser(user);
      });
  }, [userId]);
  
  return {user?.name};
}

// ✅ GOOD - Business logic in service
export class UserService {
  async getUserWithVotingStatus(userId: string): Promise {
    const user = await userRepository.getById(userId);
    return {
      ...user,
      canVote: user.age >= 18, // Business logic in service
    };
  }
}

export function UserProfile({ userId }: { userId: string }) {
  const { data: user } = useQuery(() => userService.getUserWithVotingStatus(userId));
  return {user?.name}; // Component only handles presentation
}
```

## File Organization Best Practices

### 15. File Naming Conventions

**React/TypeScript:**
- Components: PascalCase with extension: `UserCard.tsx`, `LoginForm.tsx`
- Hooks: camelCase with "use" prefix: `useAuth.ts`, `useLocalStorage.ts`
- Services: camelCase with "service" suffix: `userService.ts`, `authService.ts`
- Utils: camelCase: `format.ts`, `validation.ts`
- Types: camelCase: `user.types.ts`, `api.types.ts` or `types.ts`
- Constants: camelCase or SCREAMING_SNAKE_CASE: `routes.ts`, `API_ENDPOINTS.ts`

**Python:**
- Modules: snake_case: `user_service.py`, `data_loader.py`
- Classes: PascalCase in snake_case file: `UserService` in `user_service.py`
- Tests: prefix with `test_`: `test_user_service.py`

### 16. File Size Guidelines

- **Components**: Target <250 lines. If larger, split into sub-components.
- **Services**: Target <300 lines. If larger, split into multiple services.
- **Utility files**: Target <200 lines. Group related utilities.
- **If a file exceeds these sizes**, ask: "Is this file doing too much? Can I split it?"

### 17. Index File Usage

Use index files to create clean public APIs for modules:
```typescript
// features/users/index.ts
export { UserList, UserCard, UserForm } from './components';
export { useUsers, useUserById } from './hooks';
export { userService } from './services';
export type { User, UserFilters, CreateUserDto } from './types';

// Now consumers can import cleanly
import { UserList, useUsers, userService } from '@/features/users';
// Instead of:
// import { UserList } from '@/features/users/components/UserList';
// import { useUsers } from '@/features/users/hooks/useUsers';
```

**Don't overuse:** Index files that just re-export everything can make debugging harder.

### 18. Avoid Circular Dependencies

Circular dependencies cause hard-to-debug issues. Structure imports as a directed acyclic graph (DAG).
```typescript
// ❌ BAD - Circular dependency
// userService.ts
import { productService } from './productService';

// productService.ts
import { userService } from './userService'; // Circular!

// ✅ GOOD - Extract shared code to a lower level
// shared/types.ts
export interface User {}
export interface Product {}

// userService.ts
import type { Product } from './shared/types';

// productService.ts
import type { User } from './shared/types';
```

**Detection:** TypeScript compiler and bundlers will warn about circular dependencies.

## Code Organization Patterns

### 19. Co-location Principle

Keep related files close together. If files are always changed together, they should be near each other.
```
// ✅ GOOD - Related files together
features/users/
  UserList.tsx
  UserList.test.tsx
  UserList.styles.ts       # If using CSS-in-JS
  useUsers.ts
  useUsers.test.ts

// ❌ BAD - Related files scattered
components/UserList.tsx
tests/UserList.test.tsx
hooks/useUsers.ts
tests/useUsers.test.tsx
```

### 20. Screaming Architecture

Project structure should scream what the application does, not what framework it uses.
```
// ✅ GOOD - Clear what app does
features/
  authentication/
  user-management/
  order-processing/
  inventory-tracking/

// ❌ BAD - Only shows it's a Next.js app
pages/
components/
hooks/
api/
```

### 21. Shared vs. Feature-Specific Code

**Shared code** (`/shared`, `/common`, `/lib`): Used by 3+ features
**Feature-specific code**: Lives inside the feature folder
```
// ✅ GOOD
shared/
  utils/
    format.ts              # Used by many features
    
features/
  users/
    utils/
      calculateUserScore.ts  # Only used in users feature

// ❌ BAD
shared/
  utils/
    calculateUserScore.ts   # Only used once, not shared
```

**Rule of three:** Code becomes "shared" when you need it in 3 places, not 2. Before that, duplicate is okay.

### 22. Barrel Exports (Use Sparingly)

Barrel files (index.ts that re-exports) are useful but can slow down build times.
```typescript
// ✅ GOOD - Barrel for public API
// features/users/index.ts
export { UserList } from './components/UserList';
export { useUsers } from './hooks/useUsers';

// ❌ BAD - Barrel that exports everything
// components/index.ts
export * from './Button';
export * from './Input';
export * from './Card';
// ... 50 more components
// This slows down build because all files must be parsed even if not used
```

**Better approach:** Import directly when possible, use barrels only for public APIs.

### 23. Configuration Management

Keep configuration separate and environment-aware.
```typescript
// config/env.ts
import { z } from 'zod';

const envSchema = z.object({
  API_URL: z.string().url(),
  API_KEY: z.string().min(1),
  ENABLE_ANALYTICS: z.string().transform(s => s === 'true'),
});

export const env = envSchema.parse(process.env);

// Usage elsewhere
import { env } from '@/config/env';
console.log(env.API_URL); // Type-safe, validated
```

### 24. Constants Organization

Group constants by domain, not all in one file.
```typescript
// ✅ GOOD - Grouped by domain
constants/
  routes.ts              # Route paths
  errors.ts              # Error messages/codes
  validation.ts          # Validation rules
  api-endpoints.ts       # API URLs

// ❌ BAD - Everything in one file
constants/
  index.ts               # 500 lines of unrelated constants
```

## Testing Organization

### 25. Test File Location

**Option 1 (Recommended):** Co-locate tests with source files
```
features/users/
  UserService.ts
  UserService.test.ts
  UserList.tsx
  UserList.test.tsx
```

**Option 2:** Mirror source structure in tests folder
```
src/features/users/UserService.ts
tests/features/users/UserService.test.ts
```

**Choose one and be consistent.**

### 26. Test Organization

Group tests by what they're testing, not by type.
```typescript
// ✅ GOOD - Organized by feature
describe('UserService', () => {
  describe('getUsers', () => {
    it('returns all users');
    it('filters inactive users');
    it('handles empty response');
  });
  
  describe('createUser', () => {
    it('creates user with valid data');
    it('throws error for invalid data');
  });
});

// ❌ BAD - Organized by test type
describe('UserService unit tests', () => {
  it('getUsers returns all users');
  it('createUser creates user');
});

describe('UserService integration tests', () => {
  it('getUsers works with real API');
});
```

## Documentation & README

### 27. README Structure

Every module/feature should have clear documentation.

**Minimum README sections:**
```markdown
# Project Name

## Description
What does this do? Why does it exist?

## Installation
How to set up locally

## Configuration
What environment variables are needed? (reference .env.example)

## Usage
How to run, test, deploy

## Project Structure
High-level overview of folders

## Contributing
How to contribute (if open source)

## License
```

### 28. Code Documentation

Use comments for "why", not "what":
```typescript
// ❌ BAD - Obvious from code
// Loop through users
for (const user of users) {
  // Check if user is active
  if (user.isActive) {
    // Add to array
    activeUsers.push(user);
  }
}

// ✅ GOOD - Explains why
// We only notify active users because suspended users
// shouldn't receive promotional emails per GDPR requirements
const activeUsers = users.filter(u => u.isActive);
```

## Refactoring Indicators

### 29. When to Refactor Project Structure

**Signs you need to refactor:**
- Finding files takes too long
- Changing one feature requires touching many unrelated files
- Deep import paths: `../../../utils/format`
- Circular dependencies
- Files over 500 lines
- Too much code in "utils" or "helpers" folders (code smell)
- Unclear where new code should go

**How to refactor:**
1. Identify the pain point
2. Propose new structure
3. Move one feature as proof of concept
4. Get team buy-in
5. Gradually migrate other features
6. Update documentation

### 30. Gradual Migration Strategy

Don't rewrite everything at once. Migrate gradually:
```
my-app/
  legacy/              # Old structure (being phased out)
    components/
    utils/
  features/            # New structure (being adopted)
    users/
    products/
  
// Over time, move from legacy/ to features/
// Delete legacy/ when empty
```

## Anti-Patterns to Avoid

### 31. God Objects/Files

Files or classes that do everything. Signs: >500 lines, name like "Utils" or "Helpers".
```typescript
// ❌ BAD - God object
export class Utils {
  static formatDate() {}
  static validateEmail() {}
  static sortUsers() {}
  static calculatePrice() {}
  static sendEmail() {}
  // ... 50 more unrelated methods
}

// ✅ GOOD - Focused modules
export class DateFormatter {
  static format() {}
}

export class EmailValidator {
  static validate() {}
}
```

### 32. Shotgun Surgery

Changing one feature requires changing many files across the codebase.

**Solution:** Keep related code together (feature-based organization).

### 33. Leaky Abstractions

Implementation details leaking through abstraction boundaries.
```typescript
// ❌ BAD - Leaky abstraction
export class UserService {
  async getUsers() {
    // Returns Prisma model directly (leaks database implementation)
    return prisma.user.findMany();
  }
}

// ✅ GOOD - Clean abstraction
export class UserService {
  async getUsers(): Promise {
    const prismaUsers = await prisma.user.findMany();
    // Convert to domain model (hides database implementation)
    return prismaUsers.map(pu => this.toDomainModel(pu));
  }
}
```

### 34. Tight Coupling

Modules that can't be changed independently.
```typescript
// ❌ BAD - Tight coupling
import { UserService } from '@/features/users/UserService';

export class OrderService {
  // Directly depends on concrete class
  private userService = new UserService();
}

// ✅ GOOD - Loose coupling via interfaces
export class OrderService {
  constructor(private userService: IUserService) {} // Depends on interface
}
```

---

## Quick Reference - Architecture & Modularity

### Core Principles
- Separation of Concerns
- High Cohesion, Loose Coupling
- Single Responsibility Principle
- DRY (code repeated 3+ times → extract)
- YAGNI (don't build until needed)
- KISS (prefer simple solutions)

### Project Organization
- **Feature-based** over type-based
- **Co-locate** related files
- **Screaming architecture** (structure shows what app does)
- **Shared code** only when used by 3+ features

### Layered Architecture
```
Presentation (Components/Controllers)
     ↓
Business Logic (Services)
     ↓
Data Access (Repositories)
     ↓
Database/APIs
```

### Module Design
- Public API via index.ts
- Hide implementation details
- Clear boundaries
- Testable (dependency injection)

### File Organization
- Components: <250 lines
- Services: <300 lines
- Clear naming conventions
- Avoid circular dependencies

### Patterns to Use
- Feature-based organization
- Dependency injection
- Repository pattern
- Service layer
- Factory pattern
- Composition over inheritance

### Anti-Patterns to Avoid
- God objects (files that do everything)
- Shotgun surgery (one change = many files)
- Leaky abstractions
- Tight coupling
- Deep inheritance
- Everything in "utils"

### When to Refactor
- Finding files takes too long
- Deep import paths (../../../)
- Files >500 lines
- Circular dependencies
- Unclear where new code goes
- Too much in utils/helpers