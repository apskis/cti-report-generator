# Versioning Rulebook for Application Development

## Overview
This document establishes the versioning standards for all application development. Follow these rules consistently to maintain clear version history and communicate changes effectively to users.

## Version Format
Use **Semantic Versioning (SemVer)** with the format: `MAJOR.MINOR.PATCH`

### Version Components

**MAJOR.MINOR.PATCH**
- **MAJOR**: Incompatible API changes or significant architectural changes
- **MINOR**: New features added in a backwards compatible manner
- **PATCH**: Backwards compatible bug fixes

### Examples
- `1.0.0` → Initial stable release
- `1.0.1` → Bug fix release
- `1.1.0` → New feature added
- `2.0.0` → Breaking changes introduced

## When to Increment Each Component

### PATCH Version (x.x.PATCH)
Increment when you make backwards compatible bug fixes:

**Examples:**
- Fixed crash when clicking specific button
- Corrected text alignment issue
- Resolved memory leak
- Fixed incorrect calculation
- Patched security vulnerability (non breaking)
- Corrected typos in UI text
- Fixed broken link or image
- Resolved performance regression

**Rule:** If you're fixing something that was broken, increment PATCH.

### MINOR Version (x.MINOR.x)
Increment when you add new backwards compatible functionality:

**Examples:**
- Added new feature or capability
- Enhanced existing feature with new options
- Introduced new UI component
- Added new API endpoint
- Implemented new settings or preferences
- Added support for new file format
- Introduced new integration
- Added localization for new language

**Rules:**
- Reset PATCH to 0 when incrementing MINOR (e.g., `1.2.3` → `1.3.0`)
- If you're adding something new without breaking existing functionality, increment MINOR

### MAJOR Version (MAJOR.x.x)
Increment when you make incompatible changes:

**Examples:**
- Breaking API changes
- Removed features or functionality
- Changed data structures incompatibly
- Major architectural rewrite
- Changed behavior of existing features significantly
- Updated dependencies with breaking changes
- Changed authentication mechanism
- Removed support for old formats

**Rules:**
- Reset MINOR and PATCH to 0 when incrementing MAJOR (e.g., `1.9.5` → `2.0.0`)
- If existing users will need to change how they use your app, increment MAJOR

## Pre Release Versions

### Development Versions
Use suffixes for pre release versions:

**Alpha:** `1.2.0-alpha.1`
- Early development, unstable
- Features incomplete
- May have significant bugs

**Beta:** `1.2.0-beta.1`
- Feature complete but needs testing
- May have minor bugs
- Ready for testing by early adopters

**Release Candidate:** `1.2.0-rc.1`
- Potentially final version
- No known critical bugs
- Ready for final testing before release

### Pre Release Naming
Format: `MAJOR.MINOR.PATCH-identifier.number`

Examples:
- `2.0.0-alpha.1`
- `2.0.0-alpha.2`
- `2.0.0-beta.1`
- `2.0.0-rc.1`
- `2.0.0` (final release)

## Special Cases

### Initial Development
- Start with `0.1.0` for first development version
- Use `0.x.x` for initial development (indicates API instability)
- First stable public release should be `1.0.0`

### Version 0.x.x Rules
During initial development (version 0.x.x):
- Anything may change at any time
- MINOR version increments may include breaking changes
- Move to `1.0.0` when you're ready to declare a stable API

### Hot Fixes
For urgent production fixes:
- Create from production branch
- Increment PATCH version only
- Example: `1.5.2` → `1.5.3` (urgent security fix)

## Version Control Integration

### Git Tagging
Always tag releases in Git:

```bash
git tag -a v1.2.3 -m "Release version 1.2.3"
git push origin v1.2.3
```

### Branch Strategy
- **main/master**: Current stable release
- **develop**: Next release development
- **release/x.x.x**: Preparation for specific release
- **hotfix/x.x.x**: Urgent fixes to production

### Commit Messages
Structure commit messages to support versioning:

```
type(scope): subject

[optional body]

[optional footer]
```

**Types that affect versioning:**
- `feat`: New feature (MINOR bump)
- `fix`: Bug fix (PATCH bump)
- `BREAKING CHANGE`: In footer (MAJOR bump)
- `perf`: Performance improvement (usually PATCH)
- `refactor`: Code refactoring (no version change if internal)
- `docs`: Documentation only (no version change)
- `style`: Formatting changes (no version change)
- `test`: Adding tests (no version change)
- `chore`: Maintenance tasks (no version change)

## Changelog Maintenance

### Keep a CHANGELOG.md
Document all notable changes for each version:

```markdown
# Changelog

## [1.2.0] - 2025-11-17

### Added
- New tab grouping feature
- Support for multiple AI providers

### Changed
- Improved summary generation speed

### Fixed
- Fixed crash when switching tab groups
- Corrected citation formatting

### Security
- Updated encryption for API keys

## [1.1.0] - 2025-11-10
...
```

### Changelog Categories
- **Added**: New features
- **Changed**: Changes to existing functionality
- **Deprecated**: Soon to be removed features
- **Removed**: Removed features
- **Fixed**: Bug fixes
- **Security**: Security improvements

## Package Manifests

### package.json (Node.js/Chrome Extensions)
Always update version in package.json:

```json
{
  "name": "read-my-tabs",
  "version": "1.2.3",
  "description": "..."
}
```

### manifest.json (Chrome Extensions)
Keep version synchronized:

```json
{
  "manifest_version": 3,
  "name": "Read My Tabs",
  "version": "1.2.3"
}
```

## Decision Flowchart

When making changes, ask yourself:

1. **Did I break backwards compatibility?**
   - Yes → Increment MAJOR
   - No → Continue to 2

2. **Did I add new functionality?**
   - Yes → Increment MINOR
   - No → Continue to 3

3. **Did I make backwards compatible fixes?**
   - Yes → Increment PATCH
   - No → No version change needed

## Automation Considerations

### Recommended Tools
- **semantic-release**: Automates version management
- **standard-version**: Generates changelogs and tags
- **commitlint**: Enforces commit message conventions
- **husky**: Git hooks for version checks

### CI/CD Integration
- Automatically bump versions based on commit messages
- Generate changelog from commits
- Create Git tags automatically
- Publish releases to appropriate channels

## Communication Guidelines

### Release Notes
For each version release, provide:
- Clear summary of what changed
- Migration guide for MAJOR versions
- Known issues or limitations
- Credits to contributors

### User Facing Versions
- Show version number in app UI (usually in about/settings)
- Display changelog or "What's New" on updates
- For MAJOR versions, provide upgrade guides

## Chrome Extension Specific Notes

### Store Versioning
- Chrome Web Store displays your version number
- Users see update notifications
- Review process may take time, plan accordingly

### Version Naming for Store
- Use clear, semantic versions only
- Avoid marketing names (e.g., not "Winter Release 2024")
- Keep it simple: `1.2.3` not `1.2.3.456`

## Best Practices Summary

1. **Be Consistent**: Always follow SemVer strictly
2. **Communicate Clearly**: Document what changed and why
3. **Tag Everything**: Every release gets a Git tag
4. **Maintain Changelog**: Keep users informed of changes
5. **Think About Users**: Version numbers tell users what to expect
6. **Automate When Possible**: Use tools to reduce manual errors
7. **Plan Breaking Changes**: Group them into MAJOR releases
8. **Test Pre Releases**: Use alpha/beta versions appropriately
9. **Security First**: Prioritize security patches
10. **Document Everything**: Clear commit messages and release notes

## Quick Reference Table

| Change Type | Example | Version Bump |
|------------|---------|--------------|
| Bug fix | Fixed crash | PATCH |
| Security patch | Fixed vulnerability | PATCH |
| New feature | Added export | MINOR |
| Enhancement | Improved speed | MINOR |
| Breaking change | Removed API | MAJOR |
| Refactor (internal) | Code cleanup | None |
| Documentation | Updated README | None |
| Tests | Added tests | None |

## Version History Tracking

### Minimum Required Information
For each version, track:
- Version number
- Release date
- List of changes
- Git commit hash
- Author/contributor
- Testing status

### Where to Store
- Git tags
- CHANGELOG.md
- Release notes
- Package manifest
- Documentation site

---

**Remember:** Versioning is communication. Your version numbers tell users what changed and whether they need to take action. Be clear, be consistent, and be thoughtful about version increments.