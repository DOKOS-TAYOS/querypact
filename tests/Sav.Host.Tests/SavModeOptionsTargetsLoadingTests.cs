using Microsoft.Extensions.DependencyInjection;
using Sav.Application.Abstractions;
using Sav.Domain.Errors;
using Sav.Domain.Targets;
using Sav.Host.Composition;
using Sav.Host.Configuration;
using Sav.Infrastructure.Storage.Attestations;

namespace Sav.Host.Tests;

public sealed class SavModeOptionsTargetsLoadingTests : SavEnvTestBase
{
    private static readonly byte[] HmacKey = Enumerable.Repeat((byte)0x44, 32).ToArray();

    [Fact]
    public void FromEnvironment_loads_alias_map_from_SAV_TARGETS_JSON()
    {
        using IDisposable clearFileRoot = EnvScope.Set(SavModeOptions.ConfigRootEnvironmentVariable, null);
        using IDisposable targetsJson = EnvScope.Set(
            SavModeOptions.TargetsJsonEnvironmentVariable,
            """{"prod_ro":"SAV_TARGET_PROD_RO_DSN"}""");

        SavModeOptions options = SavModeOptions.FromEnvironment(DiProfile.AnalyzeOnly);

        Assert.True(options.AliasToDsnEnvVar.TryGetValue("prod_ro", out string? envVarName));
        Assert.Equal("SAV_TARGET_PROD_RO_DSN", envVarName);
    }

    [Fact]
    public void FromEnvironment_loads_alias_map_from_targets_json_under_config_root()
    {
        string configRoot = Path.Combine(Path.GetTempPath(), "sav-targets-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(configRoot);
        try
        {
            File.WriteAllText(
                Path.Combine(configRoot, SavModeOptions.TargetsFileName),
                """{"staging_ro":"SAV_TARGET_STAGING_RO_DSN"}""");

            using IDisposable clearEnvJson = EnvScope.Set(SavModeOptions.TargetsJsonEnvironmentVariable, null);
            using IDisposable config = EnvScope.Set(SavModeOptions.ConfigRootEnvironmentVariable, configRoot);

            SavModeOptions options = SavModeOptions.FromEnvironment(DiProfile.Full);

            Assert.True(options.AliasToDsnEnvVar.TryGetValue("staging_ro", out string? envVarName));
            Assert.Equal("SAV_TARGET_STAGING_RO_DSN", envVarName);
        }
        finally
        {
            try
            {
                Directory.Delete(configRoot, recursive: true);
            }
            catch (IOException)
            {
                // best-effort cleanup
            }
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void FromEnvironment_rejects_linked_targets_file_inside_or_outside_root(bool targetInsideRoot)
    {
        string basePath = Path.Combine(Path.GetTempPath(), "sav-targets-link-" + Guid.NewGuid().ToString("N"));
        string root = Path.Combine(basePath, "config");
        Directory.CreateDirectory(root);
        try
        {
            string actual = targetInsideRoot
                ? Path.Combine(root, "actual-targets.json")
                : Path.Combine(basePath, "external-targets.json");
            File.WriteAllText(actual, """{"redirected":"SAV_UNTRUSTED_DSN"}""");
            try
            {
                File.CreateSymbolicLink(Path.Combine(root, SavModeOptions.TargetsFileName), actual);
            }
            catch (Exception ex) when (OperatingSystem.IsWindows() &&
                                       ex is UnauthorizedAccessException or IOException or PlatformNotSupportedException)
            {
                // Windows agents without symlink privileges cannot construct this fixture.
                return;
            }

            using IDisposable env = EnvScope.Set(SavModeOptions.TargetsJsonEnvironmentVariable, null);
            using IDisposable config = EnvScope.Set(SavModeOptions.ConfigRootEnvironmentVariable, root);
            SavException rejected = Assert.Throws<SavException>(
                () => SavModeOptions.FromEnvironment(DiProfile.AnalyzeOnly));
            Assert.Equal(SavErrorCode.PathNotAllowed, rejected.Code);
            Assert.DoesNotContain("SAV_UNTRUSTED_DSN", rejected.Message, StringComparison.Ordinal);
            Assert.DoesNotContain(actual, rejected.Message, StringComparison.Ordinal);
        }
        finally
        {
            try
            {
                Directory.Delete(basePath, recursive: true);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Best-effort cleanup.
            }
        }
    }

    [Fact]
    public void FromEnvironment_rejects_a_symlinked_config_root_with_targets_file()
    {
        if (OperatingSystem.IsWindows())
        {
            // Coverage of reparse-point file links is supplied by the test above.
            return;
        }

        string basePath = Path.Combine(Path.GetTempPath(), "sav-targets-root-link-" + Guid.NewGuid().ToString("N"));
        string actualRoot = Path.Combine(basePath, "actual");
        string rootLink = Path.Combine(basePath, "linked");
        Directory.CreateDirectory(actualRoot);
        try
        {
            File.WriteAllText(
                Path.Combine(actualRoot, SavModeOptions.TargetsFileName),
                """{"redirected":"SAV_UNTRUSTED_DSN"}""");
            Directory.CreateSymbolicLink(rootLink, actualRoot);

            using IDisposable env = EnvScope.Set(SavModeOptions.TargetsJsonEnvironmentVariable, null);
            using IDisposable config = EnvScope.Set(SavModeOptions.ConfigRootEnvironmentVariable, rootLink);
            SavException rejected = Assert.Throws<SavException>(
                () => SavModeOptions.FromEnvironment(DiProfile.Full));

            Assert.Equal(SavErrorCode.PathNotAllowed, rejected.Code);
            Assert.DoesNotContain("SAV_UNTRUSTED_DSN", rejected.Message, StringComparison.Ordinal);
        }
        finally
        {
            try
            {
                Directory.Delete(basePath, recursive: true);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Best-effort cleanup.
            }
        }
    }

    [Fact]
    public void FromEnvironment_without_targets_file_still_loads_environment_mapping()
    {
        string root = Path.Combine(Path.GetTempPath(), "sav-targets-optional-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using IDisposable config = EnvScope.Set(SavModeOptions.ConfigRootEnvironmentVariable, root);
            using IDisposable targets = EnvScope.Set(
                SavModeOptions.TargetsJsonEnvironmentVariable,
                """{"prod_ro":"SAV_TARGET_PROD_RO_DSN"}""");
            SavModeOptions options = SavModeOptions.FromEnvironment(DiProfile.AnalyzeOnly);
            Assert.Equal("SAV_TARGET_PROD_RO_DSN", options.AliasToDsnEnvVar["prod_ro"]);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void Full_di_recognizes_alias_loaded_from_environment_map()
    {
        string dsnEnvVar = "SAV_TEST_HOST_ALIAS_DSN_" + Guid.NewGuid().ToString("N");
        string dsnValue = "Host=127.0.0.1;Username=ro;Password=x;Database=sav";
        Environment.SetEnvironmentVariable(dsnEnvVar, dsnValue);

        try
        {
            using IDisposable targetsJson = EnvScope.Set(
                SavModeOptions.TargetsJsonEnvironmentVariable,
                $$"""{"ci_ro":"{{dsnEnvVar}}"}""");
            using IDisposable hmac = EnvScope.Set(
                AttestationHmacKeyDecoder.EnvironmentVariableName,
                "base64:" + Convert.ToBase64String(HmacKey));

            SavModeOptions options = SavModeOptions.FromEnvironment(DiProfile.Full);
            Assert.Contains("ci_ro", options.AliasToDsnEnvVar.Keys);

            string storeRoot = Path.Combine(Path.GetTempPath(), "sav-attest-" + Guid.NewGuid().ToString("N"));
            options = new SavModeOptions
            {
                Mode = DiProfile.Full,
                ConfigRoot = options.ConfigRoot,
                AttestationStoreRoot = storeRoot,
                AliasToDsnEnvVar = options.AliasToDsnEnvVar,
            };

            using ServiceProvider sp = Program.BuildServiceProvider(
                DiProfile.Full,
                options: options,
                hmacKey: HmacKey);

            ITargetAliasResolver resolver = sp.GetRequiredService<ITargetAliasResolver>();
            TargetAlias alias = resolver.Resolve("ci_ro");

            Assert.Equal("ci_ro", alias.Alias);
            Assert.False(string.IsNullOrWhiteSpace(alias.Fingerprint));
            Assert.DoesNotContain(dsnValue, alias.Fingerprint, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Environment.SetEnvironmentVariable(dsnEnvVar, null);
        }
    }

    [Fact]
    public void FromEnvironment_rejects_dsn_value_in_targets_map()
    {
        using IDisposable targetsJson = EnvScope.Set(
            SavModeOptions.TargetsJsonEnvironmentVariable,
            """{"prod_ro":"Host=evil;Password=secret"}""");

        SavException ex = Assert.Throws<SavException>(() =>
            SavModeOptions.FromEnvironment(DiProfile.AnalyzeOnly));

        Assert.Equal(SavErrorCode.AliasLooksLikeDsn, ex.Code);
    }
}
