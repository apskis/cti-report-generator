# Cursor AI Development Rules - React/Next.js

These rules are specific to React and Next.js projects. Also reference CURSOR_RULES_JAVASCRIPT.md and CURSOR_RULES_UNIVERSAL.md.

## Next.js Specific

1. For Next.js projects, use client components ('use client') for forms and interactivity. Use server components for data fetching and display.

2. Follow App Router conventions: https://nextjs.org/docs/app

3. Use arrow functions for components. Export default at bottom of file.

4. Use next/image component instead of <img> tags for automatic image optimization.

5. Use next/link component for client-side navigation between pages.

6. Use next/font for optimized font loading.

7. Leverage server components by default. Only add 'use client' when you need: useState, useEffect, event handlers, browser APIs, or client-only libraries.

8. Use route handlers (app/api/route.ts) for API endpoints instead of pages/api.

9. Use server actions for form submissions and mutations when appropriate.

10. Implement proper metadata with generateMetadata() for SEO.

11. Use loading.tsx and error.tsx files for loading and error states.

12. Implement proper data fetching in server components using async/await.

## React Components

13. Keep components small and focused. If a component file exceeds 200-250 lines, consider splitting it.

14. One component per file (with exception for tightly coupled small sub-components).

15. Use functional components with hooks. Class components are legacy.

16. Name component files with PascalCase: UserProfile.tsx, not userProfile.tsx or user-profile.tsx.

17. Use descriptive component names that indicate purpose: LoginForm, not Form. UserProfileCard, not Card.

18. Extract repeated JSX patterns into components or utility functions.

## React Hooks

19. Follow Rules of Hooks: only call hooks at top level, only call from React functions.

20. useState: use for component-local state. Group related state: const [user, setUser] = useState({name: '', age: 0})

21. useEffect: clean up side effects. Return cleanup function for subscriptions, timers, event listeners:
```typescript
    useEffect(() => {
      const timer = setInterval(() => {}, 1000);
      return () => clearInterval(timer);
    }, []);
```

22. useMemo: use for expensive calculations, not for every value. Measure before optimizing.

23. useCallback: use for functions passed to optimized child components. Don't overuse.

24. useRef: use for DOM references, storing mutable values that don't trigger re-renders, or keeping previous values.

25. Custom hooks: extract reusable logic. Name with "use" prefix: useAuth, useFetch, useLocalStorage.

26. Keep useEffect dependencies accurate. Use ESLint plugin to catch issues.

27. Avoid useEffect when possible. Prefer: event handlers, derived state during render, or server components.

## State Management

28. Start with useState and useContext. Don't reach for Redux/Zustand immediately.

29. Lift state up only as high as necessary. Keep state close to where it's used.

30. Avoid prop drilling beyond 2-3 levels. Use Context API, composition, or state management library.

31. For forms, consider controlled components with useState or form libraries (React Hook Form, Formik).

32. For complex state logic, use useReducer instead of multiple useState calls.

33. For global state that needs persistence, use state management libraries: Zustand (simple), Redux Toolkit (complex), Jotai (atomic).

## Performance Optimization

34. Lazy load components with React.lazy() and Suspense for code splitting:
```typescript
    const HeavyComponent = lazy(() => import('./HeavyComponent'));
    <Suspense fallback={<Loading />}>
      <HeavyComponent />
    </Suspense>
```

35. Use dynamic imports in Next.js for code splitting: import('component').then()

36. Memoize expensive calculations with useMemo when rendering is slow.

37. Wrap functions in useCallback when passing to memoized child components.

38. Use React.memo() for components that render often with same props. Don't use everywhere.

39. Virtualize long lists with libraries like react-window or react-virtual.

40. For lists, always include unique, stable key props. Never use array index as key unless list is static and never reordered.

41. Avoid creating objects/arrays inline in JSX when passing to child components (causes re-renders):
```typescript
    // Bad
    <Child config={{option: true}} />
    
    // Good
    const config = useMemo(() => ({option: true}), []);
    <Child config={config} />
```

42. Debounce expensive operations: search inputs, resize handlers, scroll handlers.

## Props & Component API

43. Use TypeScript interfaces for props: interface UserCardProps { user: User; onEdit: () => void; }

44. Use destructuring for props: function UserCard({ user, onEdit }: UserCardProps) {}

45. Provide default props via destructuring: function Button({ variant = 'primary', ...props }) {}

46. Use children prop for composition: function Card({ children }) { return <div className="card">{children}</div> }

47. Use render props or compound components for flexible component APIs.

48. Keep prop names semantic: onUserEdit not onClick, isUserActive not isActive (unless context is obvious).

## Event Handling

49. Name event handlers with "handle" prefix: handleClick, handleSubmit, handleUserDelete

50. Pass callbacks to child components, not complex logic: <Button onClick={handleClick} /> not <Button onClick={() => complex logic} />

51. Use event.preventDefault() and event.stopPropagation() appropriately.

52. For forms, use onSubmit on <form>, not onClick on button.

## Styling with Tailwind

53. Always use Tailwind v4 syntax and refer to the docs for v4. Never use v3.

54. Mobile-first approach: base styles for mobile, then use responsive utilities (md:, lg:, xl:).

55. Use Tailwind's utility classes directly in JSX. Avoid creating CSS files unless absolutely necessary.

56. Group Tailwind classes logically: layout first, then spacing, then colors, then effects.

57. Extract repeated Tailwind patterns into reusable components, not @apply directives.

58. Use arbitrary values sparingly: w-[137px] should be avoided when w-32 or w-36 works.

59. Avoid magic numbers in Tailwind. Use design tokens from config when possible.

60. Use clsx or cn() utility for conditional classes: clsx('btn', isActive && 'btn-active')

## Data Fetching

61. In Next.js server components, fetch data directly with async/await. No need for useEffect.

62. In client components, use libraries like SWR, React Query, or fetch in useEffect.

63. Handle loading states: show spinners, skeletons, or loading text.

64. Handle error states: show error messages, retry buttons, or fallback UI.

65. Handle empty states: show "no data" messages or prompts to add data.

66. Implement proper error boundaries for component-level error handling.

67. Use Suspense for data fetching when using libraries that support it (React Query, SWR with Suspense mode).

## Forms

68. Use controlled components for form inputs when you need validation or dynamic behavior.

69. Use uncontrolled components with refs for simple forms where you just need final values.

70. Consider React Hook Form for complex forms (better performance, built-in validation).

71. Validate on submit, not on every keystroke (for better UX).

72. Show validation errors clearly next to the relevant field.

73. Disable submit button during submission to prevent double-submits.

74. Show loading state during form submission.

75. Handle server errors gracefully: show error messages, allow retry.

## Accessibility

76. Use semantic HTML: <button> for buttons, <a> for links, proper heading hierarchy (h1-h6).

77. Never use <div> with onClick for buttons. Use <button> or <a>.

78. Include alt text for images, aria-labels for icon buttons, and proper form labels.

79. Ensure keyboard navigation works: tab order, enter to submit, escape to close modals.

80. Use proper ARIA attributes when semantic HTML isn't enough: aria-expanded, aria-hidden, role.

81. Maintain sufficient color contrast (WCAG AA minimum). Use tools to check.

82. Test with keyboard only (no mouse).

83. Test with screen readers when possible.

84. Include test IDs (data-testid) on interactive elements for automated testing.

## Code Organization

85. Organize by feature or domain, not by file type:
```
    features/
      auth/
        components/
        hooks/
        utils/
      users/
        components/
        hooks/
        utils/
```

86. Keep related code together: component, its tests, its styles (if any), its hooks.

87. Create separate folders for: components/, hooks/, utils/, types/, constants/, lib/

88. Use index files to re-export, but don't overuse (can make imports confusing).

## TypeScript with React

89. Use React.FC sparingly. Explicit prop types are often clearer:
```typescript
    // Prefer this
    function Component({ name }: { name: string }) {}
    
    // Over this
    const Component: React.FC<{ name: string }> = ({ name }) => {}
```

90. Type event handlers explicitly: (e: React.MouseEvent<HTMLButtonElement>) => void

91. Type refs: const ref = useRef<HTMLDivElement>(null)

92. Use discriminated unions for component variants or state machines.

## Testing

93. Write unit tests for utility functions and complex hooks.

94. Write component tests for user interactions and conditional rendering.

95. Use React Testing Library (test behavior, not implementation).

96. Test accessibility: getByRole, getByLabelText (prefer these over getByTestId).

97. Mock API calls and external dependencies.

## Common Pitfalls to Avoid

98. Don't mutate state directly. Always use setState or state setter from useState.

99. Don't forget dependencies in useEffect. Use ESLint to catch.

100. Don't store derived state. Calculate during render instead:
```typescript
     // Bad
     const [total, setTotal] = useState(0);
     useEffect(() => {
       setTotal(price * quantity);
     }, [price, quantity]);
     
     // Good
     const total = price * quantity;
```

101. Don't use index as key when list can reorder, filter, or add/remove items.

102. Don't create components inside components (creates new instance each render).

103. Don't call hooks conditionally or in loops.

104. Don't over-optimize with memo/useMemo/useCallback everywhere. Measure first.

## Environment Variables

105. Prefix Next.js public env vars with NEXT_PUBLIC_: NEXT_PUBLIC_API_URL

106. Never expose secrets in NEXT_PUBLIC_ variables. These are sent to the browser.

107. Use .env.local for local development secrets (git-ignored by default).

108. Use .env.example to document required environment variables. (For Azure Functions, use local.settings.json.template instead.)

---

## Quick Reference - React/Next.js

### Next.js Patterns
- Server components by default
- 'use client' only for interactivity
- Use next/image, next/link, next/font
- App Router conventions
- Route handlers for APIs
- Server actions for mutations

### Components
- Functional components with hooks
- Keep small (<200-250 lines)
- One component per file
- PascalCase file names
- Descriptive names: LoginForm not Form

### Hooks
- Follow Rules of Hooks
- useState for local state
- useEffect with cleanup for side effects
- useMemo/useCallback for optimization (measure first)
- Custom hooks for reusable logic

### State Management
- Start with useState + Context
- Lift state only as needed
- No prop drilling >2-3 levels
- useReducer for complex state
- Libraries for global: Zustand, Redux, Jotai

### Performance
- Lazy load with React.lazy() + Suspense
- Stable, unique keys for lists
- React.memo() when re-rendering is slow
- Virtualize long lists
- Debounce expensive operations

### Styling (Tailwind v4)
- Utility-first
- Mobile-first (base → md: → lg:)
- Extract repeated patterns to components
- Avoid magic numbers
- Use clsx for conditional classes

### Data Fetching
- Server components: direct async/await
- Client: SWR, React Query, or useEffect
- Handle loading/error/empty states
- Error boundaries for errors

### Forms
- Controlled for validation/dynamic
- React Hook Form for complex forms
- Validate on submit
- Clear error messages
- Loading state during submission

### Accessibility
- Semantic HTML (<button>, <a>, headings)
- Alt text, aria-labels, labels
- Keyboard navigation
- WCAG AA contrast
- Test IDs for automated testing

### Common Pitfalls
- Don't mutate state
- Don't forget useEffect dependencies
- Don't store derived state
- Don't use index as key
- Don't create components inside components
- Don't over-optimize