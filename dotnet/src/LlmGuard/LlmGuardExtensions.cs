using LlmGuard;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

// Extension methods live in the namespaces of the types they extend, so they're
// available wherever IServiceCollection / IApplicationBuilder are used.
namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>Registers LlmGuard.</summary>
    public static class LlmGuardServiceCollectionExtensions
    {
        /// <summary>
        /// Registers the gateway client, middleware and handler, binding
        /// <see cref="LlmGuardOptions"/> from the <c>LlmGuard</c> configuration section.
        /// If configuration has no API key, the <c>LLMGUARD_API_KEY</c> environment variable is used.
        /// Options are validated at startup.
        /// </summary>
        /// <param name="services">The service collection.</param>
        /// <param name="configure">Optional extra configuration for non-secret settings.</param>
        public static IServiceCollection AddLlmGuard(this IServiceCollection services, Action<LlmGuardOptions>? configure = null)
        {
            var options = services.AddOptions<LlmGuardOptions>().BindConfiguration(LlmGuardOptions.SectionName);
            if (configure is not null)
            {
                options.Configure(configure);
            }
            options.PostConfigure(o =>
            {
                if (string.IsNullOrWhiteSpace(o.ApiKey))
                {
                    o.ApiKey = Environment.GetEnvironmentVariable(LlmGuardOptions.ApiKeyEnvironmentVariable);
                }
            });
            services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<LlmGuardOptions>, LlmGuardOptionsValidator>());
            options.ValidateOnStart();

            services.AddHttpClient<ILlmGuardClient, LlmGuardClient>(LlmGuardDefaults.GatewayHttpClientName, (sp, http) =>
            {
                var o = sp.GetRequiredService<IOptions<LlmGuardOptions>>().Value;
                var url = o.GatewayUrl!.ToString();
                http.BaseAddress = new Uri(url.EndsWith('/') ? url : url + "/");
                // LlmGuardClient enforces LlmGuardOptions.Timeout itself, per check
                http.Timeout = Timeout.InfiniteTimeSpan;
            });
            services.TryAddTransient<LlmGuardHandler>();
            return services;
        }

        /// <summary>Screens outgoing LLM requests made through this HttpClient.</summary>
        public static IHttpClientBuilder AddLlmGuardHandler(this IHttpClientBuilder builder)
        {
            builder.Services.TryAddTransient<LlmGuardHandler>();
            return builder.AddHttpMessageHandler<LlmGuardHandler>();
        }
    }
}

namespace Microsoft.AspNetCore.Builder
{
    /// <summary>Adds LlmGuard to the request pipeline.</summary>
    public static class LlmGuardApplicationBuilderExtensions
    {
        /// <summary>Screens requests to <see cref="LlmGuardOptions.ProtectedRoutes"/>. Call before mapping endpoints.</summary>
        public static IApplicationBuilder UseLlmGuard(this IApplicationBuilder app) =>
            app.UseMiddleware<LlmGuardMiddleware>();
    }
}

namespace LlmGuard
{
    /// <summary>Well-known names.</summary>
    public static class LlmGuardDefaults
    {
        /// <summary>Name of the HttpClient that talks to the gateway; configure it with
        /// <c>services.AddHttpClient(GatewayHttpClientName)</c> to add handlers or a proxy.</summary>
        public const string GatewayHttpClientName = "LlmGuard.Gateway";
    }

    internal sealed class LlmGuardOptionsValidator : IValidateOptions<LlmGuardOptions>
    {
        public ValidateOptionsResult Validate(string? name, LlmGuardOptions o)
        {
            var errors = new List<string>();
            if (o.GatewayUrl is null || !o.GatewayUrl.IsAbsoluteUri
                || (o.GatewayUrl.Scheme != Uri.UriSchemeHttp && o.GatewayUrl.Scheme != Uri.UriSchemeHttps))
            {
                errors.Add("LlmGuard:GatewayUrl must be an absolute http(s) URL.");
            }
            if (string.IsNullOrWhiteSpace(o.ApiKey))
            {
                errors.Add($"LlmGuard:ApiKey is not set. Provide it through configuration (e.g. the LlmGuard__ApiKey " +
                           $"environment variable or user secrets) or the {LlmGuardOptions.ApiKeyEnvironmentVariable} environment variable.");
            }
            if (o.Timeout <= TimeSpan.Zero || o.Timeout > TimeSpan.FromMinutes(1))
            {
                errors.Add("LlmGuard:Timeout must be between 0 and 1 minute.");
            }
            if (string.IsNullOrWhiteSpace(o.PromptJsonField))
            {
                errors.Add("LlmGuard:PromptJsonField must not be empty.");
            }
            if (o.MaxBodyBytes <= 0)
            {
                errors.Add("LlmGuard:MaxBodyBytes must be positive.");
            }
            if (!Enum.IsDefined(o.FailMode))
            {
                errors.Add("LlmGuard:FailMode must be FailClosed or explicit FailOpen.");
            }
            return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
        }
    }
}
