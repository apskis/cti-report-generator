# CURSOR_RULES_UX.md

## 🎯 Purpose

This document outlines proven UX/UI design best practices for creating modern, effective, and visually pleasing websites. These rules are based on usability principles, modern design systems, and real world patterns used by successful platforms.

**This project uses Tailwind CSS and shadcn/ui components.**

---

## 🛠️ Technology Stack

| Layer | Technology |
|-------|------------|
| Styling | Tailwind CSS |
| Components | shadcn/ui (built on Radix UI) |
| Icons | Lucide React |
| Animations | Tailwind + Framer Motion (optional) |
| Theming | CSS variables via Tailwind config |

### Installation Assumptions

```bash
# shadcn/ui initialized with:
npx shadcn@latest init
# Using: New York style, Zinc base color, CSS variables enabled
```

---

## 📐 Layout & Structure

### Grid System

Use Tailwind's spacing scale based on 4px increments. Prefer multiples of 4 for all spacing.

```tsx
// ✅ Good: consistent spacing
<div className="p-4 md:p-6 lg:p-8">
  <div className="space-y-4">
    <Card />
    <Card />
  </div>
</div>

// ❌ Bad: arbitrary values
<div className="p-[13px] mt-[7px]">
```

### Spacing Scale Reference

| Tailwind Class | Pixels | Use Case |
|----------------|--------|----------|
| `space-1` / `p-1` | 4px | Tight spacing, icon gaps |
| `space-2` / `p-2` | 8px | Inside buttons, small cards |
| `space-3` / `p-3` | 12px | Form inputs, compact sections |
| `space-4` / `p-4` | 16px | Default component padding |
| `space-6` / `p-6` | 24px | Card padding, section gaps |
| `space-8` / `p-8` | 32px | Large section padding |
| `space-12` / `p-12` | 48px | Page section separation |
| `space-16` / `p-16` | 64px | Hero sections, major breaks |

### Container & Max Width

```tsx
// Standard page container
<main className="mx-auto max-w-6xl px-4 sm:px-6 lg:px-8">
  {children}
</main>

// Content width for readability (prose)
<article className="mx-auto max-w-3xl">
  {content}
</article>
```

### Visual Hierarchy

```tsx
// Proper heading hierarchy
<h1 className="text-4xl font-bold tracking-tight">Page Title</h1>
<h2 className="text-2xl font-semibold">Section Title</h2>
<h3 className="text-xl font-medium">Subsection</h3>
<p className="text-base text-muted-foreground">Body text</p>
<span className="text-sm text-muted-foreground">Caption/helper</span>
```

---

## 🎨 Visual Design

### Color System

Use shadcn/ui's semantic color tokens. Never use raw hex/rgb values.

```tsx
// ✅ Good: semantic colors
<div className="bg-background text-foreground">
  <p className="text-muted-foreground">Secondary text</p>
  <Button className="bg-primary text-primary-foreground">Action</Button>
</div>

// ❌ Bad: hardcoded colors
<div className="bg-white text-black">
  <p className="text-gray-500">Secondary text</p>
</div>
```

### Color Token Reference

| Token | Light Mode | Dark Mode | Use Case |
|-------|------------|-----------|----------|
| `background` | White | Zinc 950 | Page background |
| `foreground` | Zinc 950 | Zinc 50 | Primary text |
| `muted` | Zinc 100 | Zinc 800 | Subtle backgrounds |
| `muted-foreground` | Zinc 500 | Zinc 400 | Secondary text |
| `primary` | Zinc 900 | Zinc 50 | Primary actions |
| `secondary` | Zinc 100 | Zinc 800 | Secondary actions |
| `accent` | Zinc 100 | Zinc 800 | Highlights |
| `destructive` | Red 500 | Red 900 | Errors, delete actions |
| `border` | Zinc 200 | Zinc 800 | Borders, dividers |
| `ring` | Zinc 950 | Zinc 300 | Focus rings |

### Custom Brand Colors

Add brand colors to `tailwind.config.js`:

```js
// tailwind.config.js
module.exports = {
  theme: {
    extend: {
      colors: {
        brand: {
          50: '#f0f9ff',
          100: '#e0f2fe',
          500: '#0ea5e9',
          600: '#0284c7',
          700: '#0369a1',
        }
      }
    }
  }
}
```

### Typography Scale

```tsx
// Font sizes following a consistent scale
const typographyScale = {
  xs: 'text-xs',      // 12px
  sm: 'text-sm',      // 14px
  base: 'text-base',  // 16px (body default)
  lg: 'text-lg',      // 18px
  xl: 'text-xl',      // 20px
  '2xl': 'text-2xl',  // 24px
  '3xl': 'text-3xl',  // 30px
  '4xl': 'text-4xl',  // 36px
  '5xl': 'text-5xl',  // 48px
};

// Fluid typography with clamp
<h1 className="text-3xl sm:text-4xl lg:text-5xl">
  Responsive Heading
</h1>
```

### Border Radius

Use consistent radius values:

```tsx
// Radius scale
const radiusScale = {
  none: 'rounded-none',   // 0px
  sm: 'rounded-sm',       // 2px
  DEFAULT: 'rounded-md',  // 6px (use for most elements)
  lg: 'rounded-lg',       // 8px (cards, modals)
  xl: 'rounded-xl',       // 12px (large cards)
  full: 'rounded-full',   // Pills, avatars
};

// ✅ Consistent
<Card className="rounded-lg" />
<Button className="rounded-md" />
<Avatar className="rounded-full" />
```

### Shadows

```tsx
// Shadow scale for depth
<div className="shadow-sm" />   // Subtle lift
<div className="shadow" />      // Default cards
<div className="shadow-md" />   // Elevated cards
<div className="shadow-lg" />   // Dropdowns, popovers
<div className="shadow-xl" />   // Modals
```

---

## 🌙 Dark Mode

### Implementation

Always support dark mode using Tailwind's `dark:` variant:

```tsx
// Theme toggle using next-themes or similar
<html className="dark">
  <body className="bg-background text-foreground">
```

```tsx
// Component with dark mode support
<div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800">
  <p className="text-zinc-900 dark:text-zinc-100">Content</p>
</div>

// ✅ Better: use semantic tokens (automatic dark mode)
<div className="bg-card text-card-foreground border">
  <p>Content</p>
</div>
```

### CSS Variables Setup

```css
/* globals.css */
@layer base {
  :root {
    --background: 0 0% 100%;
    --foreground: 240 10% 3.9%;
    --primary: 240 5.9% 10%;
    --primary-foreground: 0 0% 98%;
    /* ... other tokens */
  }

  .dark {
    --background: 240 10% 3.9%;
    --foreground: 0 0% 98%;
    --primary: 0 0% 98%;
    --primary-foreground: 240 5.9% 10%;
    /* ... other tokens */
  }
}
```

---

## 🖱️ Interactions & States

### Button States

All buttons must have hover, active, focus, and disabled states:

```tsx
// Using shadcn Button (states built in)
import { Button } from "@/components/ui/button"

<Button variant="default">Primary</Button>
<Button variant="secondary">Secondary</Button>
<Button variant="outline">Outline</Button>
<Button variant="ghost">Ghost</Button>
<Button variant="destructive">Delete</Button>

// Custom button with all states
<button className="
  bg-primary text-primary-foreground
  hover:bg-primary/90
  active:scale-[0.98]
  focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2
  disabled:pointer-events-none disabled:opacity-50
  transition-colors
">
  Click Me
</button>
```

### Focus States

Always provide visible focus indicators:

```tsx
// Focus ring pattern
<button className="
  focus-visible:outline-none 
  focus-visible:ring-2 
  focus-visible:ring-ring 
  focus-visible:ring-offset-2
  focus-visible:ring-offset-background
">

// For inputs
<input className="
  focus-visible:outline-none 
  focus-visible:ring-2 
  focus-visible:ring-ring
" />
```

### Loading States

Always show loading indicators:

```tsx
import { Loader2 } from "lucide-react"

// Button loading state
<Button disabled>
  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
  Please wait
</Button>

// Page/section loading
<div className="flex items-center justify-center p-8">
  <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
</div>

// Skeleton loading
import { Skeleton } from "@/components/ui/skeleton"

<div className="space-y-2">
  <Skeleton className="h-4 w-[250px]" />
  <Skeleton className="h-4 w-[200px]" />
</div>
```

---

## 🎬 Animation & Motion

### Timing Functions

```tsx
// Tailwind transition utilities
<div className="transition-all duration-200 ease-out" />   // Entrances
<div className="transition-all duration-150 ease-in" />    // Exits
<div className="transition-all duration-200 ease-in-out" /> // State changes
```

### Duration Guidelines

| Duration | Use Case |
|----------|----------|
| `duration-75` | Micro interactions (checkboxes) |
| `duration-150` | Quick state changes (hover) |
| `duration-200` | Standard transitions |
| `duration-300` | Modals, sidebars |
| `duration-500` | Page transitions (max) |

### Animation Patterns

```tsx
// Fade in
<div className="animate-in fade-in duration-200" />

// Slide in from bottom
<div className="animate-in slide-in-from-bottom-2 duration-300" />

// Scale up (modal)
<div className="animate-in zoom-in-95 duration-200" />

// Combined entrance
<div className="animate-in fade-in slide-in-from-bottom-4 duration-300" />
```

### Framer Motion Integration

```tsx
import { motion } from "framer-motion"

// Page wrapper
<motion.div
  initial={{ opacity: 0, y: 20 }}
  animate={{ opacity: 1, y: 0 }}
  exit={{ opacity: 0, y: -20 }}
  transition={{ duration: 0.2, ease: "easeOut" }}
>
  {children}
</motion.div>

// Staggered list
<motion.ul>
  {items.map((item, i) => (
    <motion.li
      key={item.id}
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: i * 0.05 }}
    >
      {item.name}
    </motion.li>
  ))}
</motion.ul>
```

---

## 📚 Z-Index Scale

Define a consistent stacking order:

```tsx
// z-index scale (add to tailwind.config.js or use inline)
const zIndexScale = {
  hide: -1,
  base: 0,
  dropdown: 10,
  sticky: 20,
  fixed: 30,
  modalBackdrop: 40,
  modal: 50,
  popover: 60,
  tooltip: 70,
  toast: 80,
  max: 9999,
};

// Usage
<header className="sticky top-0 z-20 bg-background" />
<div className="fixed inset-0 z-40 bg-black/50" /> {/* backdrop */}
<dialog className="fixed z-50" /> {/* modal */}
<div className="z-70" /> {/* tooltip */}
```

```js
// tailwind.config.js
module.exports = {
  theme: {
    extend: {
      zIndex: {
        'dropdown': '10',
        'sticky': '20',
        'fixed': '30',
        'modal-backdrop': '40',
        'modal': '50',
        'popover': '60',
        'tooltip': '70',
        'toast': '80',
      }
    }
  }
}
```

---

## 📱 Responsiveness

### Breakpoints

```tsx
// Tailwind breakpoints
// sm: 640px  (large phones, landscape)
// md: 768px  (tablets)
// lg: 1024px (laptops)
// xl: 1280px (desktops)
// 2xl: 1536px (large screens)

// Mobile-first approach (always)
<div className="
  px-4          // mobile default
  sm:px-6       // tablet
  lg:px-8       // desktop
">

// Responsive grid
<div className="
  grid 
  grid-cols-1 
  sm:grid-cols-2 
  lg:grid-cols-3 
  xl:grid-cols-4 
  gap-4 
  md:gap-6
">
```

### Responsive Typography

```tsx
// Fluid heading
<h1 className="text-2xl sm:text-3xl md:text-4xl lg:text-5xl font-bold">
  Responsive Heading
</h1>

// Using clamp (in CSS)
.fluid-heading {
  font-size: clamp(1.5rem, 4vw, 3rem);
}
```

### Mobile Navigation

```tsx
import { Sheet, SheetContent, SheetTrigger } from "@/components/ui/sheet"
import { Menu } from "lucide-react"

// Responsive nav with mobile drawer
<header className="sticky top-0 z-20 border-b bg-background">
  <nav className="mx-auto flex max-w-6xl items-center justify-between p-4">
    <Logo />
    
    {/* Desktop nav */}
    <div className="hidden md:flex items-center gap-6">
      <NavLinks />
    </div>
    
    {/* Mobile hamburger */}
    <Sheet>
      <SheetTrigger asChild className="md:hidden">
        <Button variant="ghost" size="icon">
          <Menu className="h-5 w-5" />
        </Button>
      </SheetTrigger>
      <SheetContent side="right">
        <MobileNavLinks />
      </SheetContent>
    </Sheet>
  </nav>
</header>
```

---

## 🧠 Usability Patterns

### Navigation

```tsx
// Logo always links home
<Link href="/" className="flex items-center gap-2">
  <Logo />
  <span className="font-semibold">Brand</span>
</Link>

// Active state for nav links
<Link 
  href="/about"
  className={cn(
    "text-muted-foreground hover:text-foreground transition-colors",
    pathname === "/about" && "text-foreground font-medium"
  )}
>
  About
</Link>
```

### Forms

```tsx
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"

// Always label inputs
<div className="space-y-2">
  <Label htmlFor="email">Email address</Label>
  <Input 
    id="email"
    type="email"
    placeholder="you@example.com"
  />
  <p className="text-sm text-muted-foreground">
    We'll never share your email.
  </p>
</div>

// Form with validation
import { useForm } from "react-hook-form"

<form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
  <div className="space-y-2">
    <Label htmlFor="email">Email</Label>
    <Input 
      id="email"
      {...register("email", { required: "Email is required" })}
      className={errors.email ? "border-destructive" : ""}
    />
    {errors.email && (
      <p className="text-sm text-destructive">{errors.email.message}</p>
    )}
  </div>
  
  <Button type="submit" disabled={isSubmitting}>
    {isSubmitting ? (
      <>
        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
        Submitting...
      </>
    ) : (
      "Submit"
    )}
  </Button>
</form>
```

### Error Messages

```tsx
// ❌ Bad
<p>Something went wrong</p>
<p>Error</p>

// ✅ Good
<Alert variant="destructive">
  <AlertCircle className="h-4 w-4" />
  <AlertTitle>Unable to save changes</AlertTitle>
  <AlertDescription>
    Your session has expired. Please refresh the page and try again.
  </AlertDescription>
</Alert>
```

### Empty States

```tsx
// Always provide helpful empty states
<div className="flex flex-col items-center justify-center py-12 text-center">
  <Inbox className="h-12 w-12 text-muted-foreground mb-4" />
  <h3 className="text-lg font-medium">No messages yet</h3>
  <p className="text-muted-foreground mt-1 mb-4">
    When you receive messages, they'll appear here.
  </p>
  <Button>
    <Plus className="mr-2 h-4 w-4" />
    Start a conversation
  </Button>
</div>
```

---

## 🦾 Accessibility

### Semantic HTML

```tsx
// ✅ Correct structure
<header>
  <nav aria-label="Main navigation">
    <ul role="list">
      <li><Link href="/">Home</Link></li>
    </ul>
  </nav>
</header>

<main>
  <section aria-labelledby="features-heading">
    <h2 id="features-heading">Features</h2>
  </section>
</main>

<footer>
  <nav aria-label="Footer navigation">
    ...
  </nav>
</footer>
```

### ARIA Patterns

```tsx
// Button with loading state
<Button 
  disabled={isLoading}
  aria-busy={isLoading}
  aria-label={isLoading ? "Saving..." : "Save changes"}
>
  {isLoading ? <Loader2 className="animate-spin" /> : "Save"}
</Button>

// Icon-only buttons need labels
<Button variant="ghost" size="icon" aria-label="Close menu">
  <X className="h-4 w-4" />
</Button>

// Announcing dynamic content
<div aria-live="polite" aria-atomic="true">
  {successMessage && <p>{successMessage}</p>}
</div>
```

### Keyboard Navigation

```tsx
// Ensure all interactive elements are keyboard accessible
<div 
  role="button"
  tabIndex={0}
  onClick={handleClick}
  onKeyDown={(e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      handleClick()
    }
  }}
>
  Clickable div (prefer <button> when possible)
</div>
```

### Skip Link

```tsx
// Add to layout for keyboard users
<a 
  href="#main-content"
  className="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 focus:z-50 focus:px-4 focus:py-2 focus:bg-background focus:border focus:rounded-md"
>
  Skip to main content
</a>

<main id="main-content">
  ...
</main>
```

---

## 🧩 Component Patterns

### Card

```tsx
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"

<Card>
  <CardHeader>
    <CardTitle>Card Title</CardTitle>
    <CardDescription>Card description text.</CardDescription>
  </CardHeader>
  <CardContent>
    <p>Card content goes here.</p>
  </CardContent>
  <CardFooter className="flex justify-between">
    <Button variant="outline">Cancel</Button>
    <Button>Save</Button>
  </CardFooter>
</Card>
```

### Modal/Dialog

```tsx
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"

<Dialog>
  <DialogTrigger asChild>
    <Button>Open Dialog</Button>
  </DialogTrigger>
  <DialogContent className="sm:max-w-[425px]">
    <DialogHeader>
      <DialogTitle>Edit profile</DialogTitle>
      <DialogDescription>
        Make changes to your profile here.
      </DialogDescription>
    </DialogHeader>
    <div className="py-4">
      {/* form fields */}
    </div>
    <DialogFooter>
      <Button type="submit">Save changes</Button>
    </DialogFooter>
  </DialogContent>
</Dialog>
```

### Toast Notifications

```tsx
import { useToast } from "@/hooks/use-toast"
import { Toaster } from "@/components/ui/toaster"

// In your layout
<Toaster />

// Usage
const { toast } = useToast()

toast({
  title: "Success!",
  description: "Your changes have been saved.",
})

toast({
  variant: "destructive",
  title: "Error",
  description: "Something went wrong. Please try again.",
})
```

### Data Table

```tsx
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"

<div className="rounded-md border">
  <Table>
    <TableHeader>
      <TableRow>
        <TableHead>Name</TableHead>
        <TableHead>Status</TableHead>
        <TableHead className="text-right">Amount</TableHead>
      </TableRow>
    </TableHeader>
    <TableBody>
      {data.map((row) => (
        <TableRow key={row.id}>
          <TableCell className="font-medium">{row.name}</TableCell>
          <TableCell>
            <Badge variant={row.status === "active" ? "default" : "secondary"}>
              {row.status}
            </Badge>
          </TableCell>
          <TableCell className="text-right">{row.amount}</TableCell>
        </TableRow>
      ))}
    </TableBody>
  </Table>
</div>
```

---

## 📊 Performance

### Image Optimization

```tsx
import Image from "next/image"

// Always use Next.js Image for automatic optimization
<Image
  src="/hero.jpg"
  alt="Descriptive alt text"
  width={1200}
  height={600}
  priority // for above-the-fold images
  className="rounded-lg object-cover"
/>

// Lazy load below-fold images (default behavior)
<Image
  src="/feature.jpg"
  alt="Feature description"
  width={600}
  height={400}
  loading="lazy"
/>
```

### Code Splitting

```tsx
import dynamic from "next/dynamic"

// Lazy load heavy components
const Chart = dynamic(() => import("@/components/chart"), {
  loading: () => <Skeleton className="h-[300px] w-full" />,
  ssr: false,
})

// Lazy load modals
const EditModal = dynamic(() => import("@/components/edit-modal"))
```

### Minimize Bundle

```tsx
// ✅ Import specific icons
import { Check, X, ChevronDown } from "lucide-react"

// ❌ Don't import entire library
import * as Icons from "lucide-react"
```

---

## ✅ Pre-Launch Checklist

### Visual Design
- [ ] Color palette is consistent (using CSS variables)
- [ ] Typography follows scale (no arbitrary sizes)
- [ ] Spacing uses 4px/8px grid
- [ ] Icons are consistent style (Lucide)
- [ ] Dark mode tested and working

### Interactions
- [ ] All buttons have hover, active, focus, disabled states
- [ ] Loading states implemented for async actions
- [ ] Error states are clear and helpful
- [ ] Empty states guide users to take action
- [ ] Transitions are smooth (200-300ms)

### Responsiveness
- [ ] Tested at 375px (mobile)
- [ ] Tested at 768px (tablet)
- [ ] Tested at 1024px (laptop)
- [ ] Tested at 1280px+ (desktop)
- [ ] No horizontal scrolling
- [ ] Touch targets are 44px+ on mobile

### Accessibility
- [ ] Keyboard navigation works throughout
- [ ] Focus rings visible on all interactive elements
- [ ] Color contrast passes WCAG AA
- [ ] Images have alt text
- [ ] Form inputs have labels
- [ ] Skip link present
- [ ] ARIA labels on icon buttons

### Performance
- [ ] Images optimized (WebP/AVIF)
- [ ] Lazy loading implemented
- [ ] No layout shift (CLS)
- [ ] Lighthouse score > 90

---

## 🔚 Conclusion

Good UX/UI is about **removing friction**. Follow these patterns consistently to build beautiful, functional, and inclusive web experiences with Tailwind CSS and shadcn/ui.

When in doubt:
1. Use semantic shadcn/ui tokens over raw values
2. Follow the spacing scale
3. Test on mobile first
4. Ensure keyboard accessibility
5. Show loading and error states
