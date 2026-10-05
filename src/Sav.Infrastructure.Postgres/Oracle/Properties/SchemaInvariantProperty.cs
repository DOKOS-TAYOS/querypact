using Sav.Domain.Contracts;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Properties;
using Sav.Domain.Schema;

namespace Sav.Infrastructure.Postgres.Oracle.Properties;

/// <summary>
/// <c>schema_invariant</c>: in-process compare of SchemaBefore/SchemaAfter (ephemeral only; no agent SQL).
/// </summary>
public static class SchemaInvariantProperty
{
    public static PropertyResult Evaluate(
        SchemaSnapshot before,
        SchemaSnapshot after,
        SchemaInvariantSpec spec)
    {
        ArgumentNullException.ThrowIfNull(before);
        ArgumentNullException.ThrowIfNull(after);
        ArgumentNullException.ThrowIfNull(spec);

        try
        {
            foreach (SchemaInvariantRequirement requirement in spec.Requirements)
            {
                ValidateRequirement(requirement);

                if (!TryGetDigest(after, requirement.RelationName, out string? afterDigest)
                    || afterDigest is null
                    || !TryGetRelationKind(after, requirement.RelationName, out string? afterKind)
                    || !string.Equals(afterKind, requirement.Relkind, StringComparison.Ordinal))
                {
                    return Fail();
                }

                if (!TryGetDigest(before, requirement.RelationName, out string? beforeDigest)
                    || beforeDigest is null
                    || !TryGetRelationKind(before, requirement.RelationName, out string? beforeKind)
                    || !string.Equals(beforeKind, requirement.Relkind, StringComparison.Ordinal)
                    || !string.Equals(beforeDigest, afterDigest, StringComparison.Ordinal))
                {
                    return Fail();
                }

                if (!before.RelationCountByRelkind.TryGetValue(requirement.Relkind, out long beforeCount)
                    || !after.RelationCountByRelkind.TryGetValue(requirement.Relkind, out long afterCount)
                    || beforeCount != afterCount)
                {
                    return Fail();
                }
            }

            foreach (KeyValuePair<string, bool> constraint in before.ConstraintExistsByName)
            {
                if (!constraint.Value)
                {
                    continue;
                }

                if (!after.ConstraintExistsByName.TryGetValue(constraint.Key, out bool stillExists)
                    || !stillExists)
                {
                    return Fail();
                }
            }

            foreach (KeyValuePair<string, string> constraint in before.ConstraintDigestByName)
            {
                if (!after.ConstraintDigestByName.TryGetValue(constraint.Key, out string? afterDigest)
                    || !string.Equals(constraint.Value, afterDigest, StringComparison.Ordinal))
                {
                    return Fail();
                }
            }

            return new PropertyResult("schema_invariant", PropertyStatus.Pass, null);
        }
        catch (SavException ex)
            when (ex.Code is SavErrorCode.UnsafeIdentifier or SavErrorCode.ContractInvalid)
        {
            return new PropertyResult(
                "schema_invariant",
                PropertyStatus.Error,
                ex.Code);
        }
    }

    private static void ValidateRequirement(SchemaInvariantRequirement requirement)
    {
        string[] allowRelation = [requirement.RelationName];
        _ = PgIdentifierGuard.ValidateAndQuote(requirement.RelationName, allowRelation);

        if (!SchemaInvariantRelkindVocabulary.IsSupported(requirement.Relkind))
        {
            throw new SavException(
                SavErrorCode.ContractInvalid,
                "contract_invalid: schema_invariant requirement relkind is unsupported.");
        }
    }

    private static bool TryGetDigest(
        SchemaSnapshot snapshot,
        string relationName,
        out string? digest)
    {
        if (snapshot.RelationDigestByName.TryGetValue(relationName, out digest))
        {
            return true;
        }

        string qualified = snapshot.SchemaName + "." + relationName;
        return snapshot.RelationDigestByName.TryGetValue(qualified, out digest);
    }

    private static bool TryGetRelationKind(
        SchemaSnapshot snapshot,
        string relationName,
        out string? relkind)
    {
        if (snapshot.RelationKindByName.TryGetValue(relationName, out relkind))
        {
            return true;
        }

        string qualified = snapshot.SchemaName + "." + relationName;
        return snapshot.RelationKindByName.TryGetValue(qualified, out relkind);
    }

    private static PropertyResult Fail()
    {
        return new PropertyResult(
            "schema_invariant",
            PropertyStatus.Fail,
            SavErrorCode.SchemaInvariantFailed);
    }
}
