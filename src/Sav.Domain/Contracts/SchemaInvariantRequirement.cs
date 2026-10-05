namespace Sav.Domain.Contracts;

/// <summary>
/// Relation existence requirement used by MVP-B <c>SchemaInvariantSpec</c>.
/// </summary>
public sealed record SchemaInvariantRequirement(string RelationName, string Relkind);
