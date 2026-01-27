# Cursor AI Development Rules - Azure Projects

These rules apply specifically to Azure-based projects (Azure Functions, Azure App Service, Azure Container Apps, etc.).

## Project Structure & Configuration

1. **Use `local.settings.json` for Azure Functions**: For Azure Functions projects, use `local.settings.json` instead of `.env` files. The `Values` section in `local.settings.json` automatically becomes environment variables.

2. **Include `local.settings.json.template`**: Create a template file (`local.settings.json.template`) showing required configuration without actual values. This serves the same purpose as `.env.example` for non-Azure projects.

3. **Structure of `local.settings.json`**:
```json
{
  "IsEncrypted": false,
  "Values": {
    "AzureWebJobsStorage": "UseDevelopmentStorage=true",
    "FUNCTIONS_WORKER_RUNTIME": "python",
    "KEY_VAULT_URL": "https://your-keyvault-name.vault.azure.net/",
    "ENABLED_COLLECTORS": "nvd,intel471,crowdstrike"
  },
  "ConnectionStrings": {}
}
```

4. **Git ignore `local.settings.json`**: Add `local.settings.json` to `.gitignore` to prevent committing local configuration. Commit `local.settings.json.template` instead.

## Secrets Management

5. **Use Azure Key Vault for secrets**: Store API keys, connection strings, and other sensitive data in Azure Key Vault, not in `local.settings.json` or environment variables.

6. **Only store Key Vault URL in config**: The only secret-related value that should be in `local.settings.json` is the Key Vault URL. All actual secrets should be retrieved from Key Vault at runtime.

7. **Use Managed Identity in production**: For production deployments, use Azure Managed Identity to authenticate to Key Vault instead of storing credentials.

## Azure Functions Specific

8. **Environment variables from `local.settings.json`**: Azure Functions automatically loads the `Values` section of `local.settings.json` as environment variables. Access them via `os.environ.get()` in Python or `Environment.GetEnvironmentVariable()` in C#.

9. **No need for `python-dotenv`**: Azure Functions projects don't need `python-dotenv` or `load_dotenv()` calls. The runtime handles environment variable loading automatically.

10. **Connection Strings**: Use the `ConnectionStrings` section for database and storage connection strings that need special handling by Azure Functions.

## Azure App Service / Container Apps

11. **Use Application Settings**: For Azure App Service or Container Apps, use the Azure Portal Application Settings or Azure CLI to configure environment variables. These are automatically available as environment variables.

12. **Configuration in code**: Access configuration via `os.environ.get()` in Python. No special loading is required.

## Best Practices

13. **Separate configs by environment**: Use different `local.settings.json` files or Application Settings for development, staging, and production.

14. **Document required settings**: In `local.settings.json.template`, document what each setting does and whether it's required or optional.

15. **Use Key Vault references**: In production, use Key Vault references in Application Settings (e.g., `@Microsoft.KeyVault(SecretUri=...)`) to automatically retrieve secrets.

16. **Validate configuration at startup**: Check for required configuration values at application startup and fail fast with clear error messages if missing.

## Example Template Structure

```
project-root/
├── local.settings.json          # Local development (git-ignored)
├── local.settings.json.template # Template for other developers (committed)
├── host.json                    # Azure Functions host configuration
└── function_app.py             # Function code
```

## Quick Reference

- ✅ Use `local.settings.json` for Azure Functions
- ✅ Create `local.settings.json.template` as the template
- ✅ Store secrets in Azure Key Vault
- ✅ Add `local.settings.json` to `.gitignore`
- ❌ Don't use `.env` files for Azure Functions
- ❌ Don't include `python-dotenv` in requirements
- ❌ Don't store secrets in `local.settings.json`
