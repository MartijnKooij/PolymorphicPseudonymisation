using Microsoft.Extensions.DependencyInjection;
using System;

namespace PolymorphicPseudonymisation.Service
{
    /// <summary>
    /// Extension methods to register the Decrypt service
    /// </summary>
    public static class ServiceCollectionExtensions
    {
        /// <summary>
        /// Register the decrypt service for dependency injection passing in the options
        /// required to decrypt the identities and pseudonyms
        /// </summary>
        /// <param name="services"></param>
        /// <param name="options"></param>
        public static void AddDecryptService(this IServiceCollection services, Action<DecryptOptions> options)
        {
            services.Configure(options);
            services.PostConfigure<DecryptOptions>(decryptOptions => { decryptOptions.Validate(); });
            services.AddSingleton<IDecryptService, DecryptService>();
        }
    }
}