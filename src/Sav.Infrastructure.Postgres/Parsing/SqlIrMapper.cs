using System.Collections.Concurrent;
using Google.Protobuf;
using Google.Protobuf.Reflection;
using PgSqlParser;

namespace Sav.Infrastructure.Postgres.Parsing;

/// <summary>
/// Maps libpg_query protobuf trees into the QueryPact IR facts (fail-closed risk codes).
/// </summary>
public static class SqlIrMapper
{
    private static readonly ConcurrentDictionary<MessageDescriptor, FieldDescriptor[]> DescriptorFields = new();

    /// <summary>
    /// Maps the parsed protobuf tree directly into the QueryPact IR facts without creating an intermediate JSON string.
    /// </summary>
    public static SqlIrMappedFacts Map(ParseResult parseResult)
    {
        ArgumentNullException.ThrowIfNull(parseResult);

        List<string> statementTypes = [];
        HashSet<string> tablesRead = new(StringComparer.Ordinal);
        HashSet<string> tablesWritten = new(StringComparer.Ordinal);
        HashSet<string> columnsRead = new(StringComparer.OrdinalIgnoreCase);
        HashSet<string> columnsWritten = new(StringComparer.OrdinalIgnoreCase);
        // PostgreSQL already folds unquoted AST identifiers; quoted case remains significant.
        HashSet<string> functions = new(StringComparer.Ordinal);
        HashSet<string> functionReferences = new(StringComparer.Ordinal);
        HashSet<string> operators = new(StringComparer.Ordinal);
        HashSet<string> riskCodes = new(StringComparer.Ordinal);
        HashSet<string> typeReferences = new(StringComparer.Ordinal);
        CollectTypeReferences(parseResult, typeReferences, riskCodes);
        bool hasDynamicSql = false;
        bool hasStar = false;
        bool hasNestedWrite = false;

        foreach (var rawStatement in parseResult.Stmts)
        {
            IMessage? statementNode = rawStatement.Stmt;
            FieldDescriptor? statementField = statementNode is null
                ? null
                : GetFields(statementNode).FirstOrDefault(field =>
                    field.ContainingOneof is not null && field.Accessor.HasValue(statementNode));
            if (statementNode is null || statementField is null ||
                statementField.Accessor.GetValue(statementNode) is not IMessage statement)
            {
                riskCodes.Add("unresolved_mapping");
                continue;
            }

            string mapped = MapStatementType(statementField.JsonName);
            statementTypes.Add(mapped);
            if (mapped == "MergeStmt")
            {
                riskCodes.Add("unsupported_construct");
            }

            if (ContainsSelectInto(statement))
            {
                riskCodes.Add("unsupported_construct");
            }

            if (mapped is "Execute" or "Prepare" or "Copy")
            {
                hasDynamicSql = true;
                riskCodes.Add("unsupported_construct");
            }

            bool predicatePresent = HasDirectPredicate(statement);
            if (HasPotentialWholeRowReference(statement, new HashSet<string>(StringComparer.Ordinal)))
            {
                riskCodes.Add("unsupported_construct");
            }

            WalkMessage(
                statement,
                statementField.JsonName,
                columnsRead,
                columnsWritten,
                functions,
                functionReferences,
                operators,
                ref hasStar,
                ref hasNestedWrite);

            if ((mapped is "Update" or "Delete") && !predicatePresent)
            {
                riskCodes.Add("missing_predicate");
            }

            if (hasNestedWrite)
            {
                riskCodes.Add("unsupported_construct");
            }
        }

        if (hasStar)
        {
            riskCodes.Add("unsupported_construct");
        }

        // CTE bindings are lexical: in a non-recursive WITH definition its own name
        // is not yet visible. Assign read/write roles in this scoped pass so a CTE
        // source cannot acquire the identity of a same-named physical destination.
        HashSet<string> physicalRelations = new(StringComparer.Ordinal);
        foreach (var rawStatement in parseResult.Stmts)
        {
            if (rawStatement.Stmt is null ||
                !CollectPhysicalRelations(rawStatement.Stmt, new HashSet<string>(StringComparer.Ordinal),
                    physicalRelations, tablesRead, tablesWritten))
            {
                riskCodes.Add("unsupported_construct");
            }
        }

        List<string> unresolved = [.. physicalRelations.OrderBy(x => x, StringComparer.Ordinal)];

        return new SqlIrMappedFacts(
            StatementTypes: statementTypes,
            TablesRead: [.. tablesRead.OrderBy(x => x, StringComparer.Ordinal)],
            TablesWritten: [.. tablesWritten.OrderBy(x => x, StringComparer.Ordinal)],
            ColumnsRead: [.. columnsRead.OrderBy(x => x, StringComparer.OrdinalIgnoreCase)],
            ColumnsWritten: [.. columnsWritten.OrderBy(x => x, StringComparer.OrdinalIgnoreCase)],
            Functions: [.. functions.OrderBy(x => x, StringComparer.Ordinal)],
            FunctionReferences: [.. functionReferences.OrderBy(x => x, StringComparer.Ordinal)],
            Operators: [.. operators.OrderBy(x => x, StringComparer.Ordinal)],
            HasMultipleStatements: parseResult.Stmts.Count > 1 || statementTypes.Count > 1,
            HasDynamicSql: hasDynamicSql,
            UnresolvedObjects: unresolved,
            RiskCodes: [.. riskCodes.OrderBy(x => x, StringComparer.Ordinal)])
        {
            TypeReferences = [.. typeReferences.OrderBy(x => x, StringComparer.Ordinal)],
            Int4ConstantProjectionCount = riskCodes.Count == 0 ? GetInt4ConstantProjectionCount(parseResult) : 0,
        };
    }

    // This pass is deliberately independent of the flat IR collector: RangeVar identities
    // depend on the active WITH scope, not on the set of names declared anywhere in the tree.
    // An unrecognized CTE shape fails closed instead of silently dropping catalog checks.
    private static bool CollectPhysicalRelations(
        IMessage node,
        HashSet<string> visibleCtes,
        HashSet<string> physicalRelations,
        HashSet<string> tablesRead,
        HashSet<string> tablesWritten,
        bool physicalTarget = false,
        bool writeTargetRelation = false)
    {
        if (node is RangeVar)
        {
            FieldDescriptor[] fields = GetFields(node);
            string? relation = fields.FirstOrDefault(static f => f.JsonName == "relname")
                ?.Accessor.GetValue(node) as string;
            string? schema = fields.FirstOrDefault(static f => f.JsonName == "schemaname")
                ?.Accessor.GetValue(node) as string;
            if (string.IsNullOrWhiteSpace(relation))
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(schema) || physicalTarget || !visibleCtes.Contains(relation))
            {
                string table = !string.IsNullOrWhiteSpace(schema) ? schema + "." + relation : relation;
                physicalRelations.Add(table);
                (writeTargetRelation ? tablesWritten : tablesRead).Add(table);
            }

            return true;
        }

        FieldDescriptor? withField = GetFields(node).FirstOrDefault(field =>
            field.JsonName == "withClause" &&
            field.FieldType == FieldType.Message &&
            field.Accessor.HasValue(node));
        if (withField is not null && withField.Accessor.GetValue(node) is IMessage withClause)
        {
            FieldDescriptor? ctesField = GetFields(withClause).FirstOrDefault(static field =>
                field.JsonName == "ctes" && field.IsRepeated && field.FieldType == FieldType.Message);
            if (ctesField is null)
            {
                return false;
            }

            List<(string Name, IMessage Query)> definitions = [];
            HashSet<string> declared = new(StringComparer.Ordinal);
            foreach (IMessage wrapper in (System.Collections.IEnumerable)ctesField.Accessor.GetValue(withClause))
            {
                IMessage? cte = wrapper.Descriptor.Name == "CommonTableExpr"
                    ? wrapper
                    : GetFields(wrapper).FirstOrDefault(field =>
                        field.JsonName == "CommonTableExpr" &&
                        field.FieldType == FieldType.Message &&
                        field.Accessor.HasValue(wrapper))?.Accessor.GetValue(wrapper) as IMessage;
                if (cte is null)
                {
                    return false;
                }

                string? name = GetFields(cte).FirstOrDefault(static field => field.JsonName == "ctename")
                    ?.Accessor.GetValue(cte) as string;
                FieldDescriptor? queryField = GetFields(cte).FirstOrDefault(field =>
                    field.JsonName == "ctequery" &&
                    field.FieldType == FieldType.Message &&
                    field.Accessor.HasValue(cte));
                if (string.IsNullOrWhiteSpace(name) || !declared.Add(name) ||
                    queryField?.Accessor.GetValue(cte) is not IMessage query)
                {
                    return false;
                }

                definitions.Add((name, query));
            }

            bool recursive = GetFields(withClause).FirstOrDefault(static field => field.JsonName == "recursive")
                ?.Accessor.GetValue(withClause) is true;
            HashSet<string> local = new(visibleCtes, StringComparer.Ordinal);
            if (recursive)
            {
                foreach (var definition in definitions)
                {
                    local.Add(definition.Name);
                }
            }

            foreach ((string name, IMessage query) in definitions)
            {
                // Non-recursive definitions can see earlier siblings, but not themselves
                // or later siblings. Recursive WITH makes all sibling names visible.
                if (!CollectPhysicalRelations(query, local, physicalRelations, tablesRead, tablesWritten))
                {
                    return false;
                }

                if (!recursive)
                {
                    local.Add(name);
                }
            }

            // The WITH names are now visible in the statement body and nested queries.
            return GetFields(node)
                .Where(field => field != withField)
                .All(field => CollectPhysicalRelationsField(node, field, local, physicalRelations,
                    tablesRead, tablesWritten, physicalTarget, writeTargetRelation));
        }

        return GetFields(node).All(field =>
            CollectPhysicalRelationsField(node, field, visibleCtes, physicalRelations,
                tablesRead, tablesWritten, physicalTarget, writeTargetRelation));
    }

    private static bool CollectPhysicalRelationsField(
        IMessage node,
        FieldDescriptor field,
        HashSet<string> visibleCtes,
        HashSet<string> physicalRelations,
        HashSet<string> tablesRead,
        HashSet<string> tablesWritten,
        bool physicalTarget,
        bool writeTargetRelation)
    {
        if (field.FieldType != FieldType.Message)
        {
            return true;
        }

        // OF names reference range bindings in this query level; they do not declare
        // additional physical sources. Those sources are collected from FROM under
        // their lexical WITH scope, preserving schemas and read/write roles.
        if (node is LockingClause && field.JsonName == "lockedRels")
        {
            return true;
        }

        // DML/DDL targets always denote physical relations, even when a WITH name
        // shadows the same identifier in source expressions.
        bool relationTarget = (field.JsonName is "relation" or "Relation") &&
            (node.Descriptor.Name is "InsertStmt" or "UpdateStmt" or "DeleteStmt" or
                "MergeStmt" or "CopyStmt" or "CreateStmt" or "AlterTableStmt" or "IndexStmt");
        bool target = physicalTarget || relationTarget ||
            (node.Descriptor.Name == "IntoClause" && field.JsonName == "rel") ||
            (node.Descriptor.Name == "TruncateStmt" && field.JsonName == "relations");

        // A write role follows only a destination edge, never the entire DML subtree.
        // INSERT SELECT, UPDATE FROM, DELETE USING and expression subqueries are reads.
        // RangeTableSample.relation is a source; physical identity alone is not write intent.
        bool written = writeTargetRelation || relationTarget ||
            (node.Descriptor.Name == "IntoClause" && field.JsonName == "rel") ||
            (node.Descriptor.Name == "SelectStmt" && field.JsonName == "intoClause");
        if (field.IsRepeated)
        {
            foreach (IMessage child in (System.Collections.IEnumerable)field.Accessor.GetValue(node))
            {
                if (!CollectPhysicalRelations(child, visibleCtes, physicalRelations,
                    tablesRead, tablesWritten, target, written))
                {
                    return false;
                }
            }

            return true;
        }

        return !field.Accessor.HasValue(node) ||
            field.Accessor.GetValue(node) is not IMessage nested ||
            CollectPhysicalRelations(nested, visibleCtes, physicalRelations,
                tablesRead, tablesWritten, target, written);
    }

    // The raw parser does not distinguish a bare column name from a whole-row
    // reference when it matches a visible range binding. Reject the ambiguous form
    // rather than allowing a composite value to bypass deniedColumns. Qualified
    // column references (e.g. u.email) remain supported.
    private static bool HasPotentialWholeRowReference(
        IMessage node,
        HashSet<string> outerBindings)
    {
        HashSet<string> bindings = outerBindings;
        if (node.Descriptor.Name is "SelectStmt" or "InsertStmt" or "UpdateStmt" or "DeleteStmt" or "MergeStmt")
        {
            bindings = new HashSet<string>(outerBindings, StringComparer.Ordinal);
            foreach (FieldDescriptor field in GetFields(node))
            {
                if (field.FieldType != FieldType.Message ||
                    !(field.JsonName is "fromClause" or "usingClause" or "relation"))
                {
                    continue;
                }

                if (field.IsRepeated)
                {
                    foreach (IMessage source in (System.Collections.IEnumerable)field.Accessor.GetValue(node))
                    {
                        AddRangeBindings(source, bindings);
                    }
                }
                else if (field.Accessor.HasValue(node) && field.Accessor.GetValue(node) is IMessage rangeItem)
                {
                    AddRangeBindings(rangeItem, bindings);
                }
            }
        }

        if (node.Descriptor.Name == "JoinExpr" && GetFields(node).Any(field =>
                field.JsonName == "isNatural" && field.Accessor.GetValue(node) is true))
        {
            // NATURAL JOIN chooses its implicit keys from catalog columns. The raw
            // tree cannot enumerate them, so deniedColumns cannot be enforced.
            return true;
        }

        if (node is ColumnRef column && column.Fields.Count is 1 or 2)
        {
            List<string> parts = [];
            foreach (IMessage part in column.Fields)
            {
                if (!TryGetStringLeaf(part, out string? name) || string.IsNullOrWhiteSpace(name))
                {
                    parts.Clear();
                    break;
                }

                parts.Add(name);
            }

            if (parts.Count == column.Fields.Count && bindings.Contains(string.Join(".", parts)))
            {
                return true;
            }
        }

        foreach (FieldDescriptor field in GetFields(node))
        {
            if (field.FieldType != FieldType.Message)
            {
                continue;
            }

            HashSet<string> childBindings = bindings;
            if ((node.Descriptor.Name == "CommonTableExpr" && field.JsonName == "ctequery") ||
                (node.Descriptor.Name == "RangeSubselect" && field.JsonName == "subquery" &&
                 !GetFields(node).Any(candidate => candidate.JsonName == "lateral" &&
                     candidate.Accessor.GetValue(node) is true)))
            {
                // CTE definitions and non-LATERAL FROM subqueries cannot reference
                // outer range bindings. Expression subqueries and LATERAL may.
                childBindings = new HashSet<string>(StringComparer.Ordinal);
            }

            if (field.IsRepeated)
            {
                foreach (IMessage child in (System.Collections.IEnumerable)field.Accessor.GetValue(node))
                {
                    if (HasPotentialWholeRowReference(child, childBindings))
                    {
                        return true;
                    }
                }
            }
            else if (field.Accessor.HasValue(node) && field.Accessor.GetValue(node) is IMessage nested &&
                     HasPotentialWholeRowReference(nested, childBindings))
            {
                return true;
            }
        }

        return false;
    }

    private static void AddRangeBindings(IMessage node, HashSet<string> bindings)
    {
        if (node.Descriptor.Name == "JoinExpr" &&
            GetAliasName(node, "join_using_alias") is string usingAlias &&
            !string.IsNullOrWhiteSpace(usingAlias))
        {
            // USING aliases name only the merged columns. They do not hide the
            // bindings of the join's left and right inputs.
            bindings.Add(usingAlias);
        }

        string? alias = GetAliasName(node);
        if (!string.IsNullOrWhiteSpace(alias))
        {
            bindings.Add(alias);
            return;
        }

        if (node is RangeVar)
        {
            string? relation = GetFields(node).FirstOrDefault(static field => field.JsonName == "relname")
                ?.Accessor.GetValue(node) as string;
            string? schema = GetFields(node).FirstOrDefault(static field => field.JsonName == "schemaname")
                ?.Accessor.GetValue(node) as string;
            if (!string.IsNullOrWhiteSpace(relation))
            {
                bindings.Add(relation);
                if (!string.IsNullOrWhiteSpace(schema))
                {
                    bindings.Add(schema + "." + relation);
                }
            }

            return;
        }

        // A subquery without a range alias does not expose its inner bindings to
        // the enclosing query. A join alias, when present, hides its constituents.
        if (node.Descriptor.Name is "RangeSubselect" or "RangeFunction" or "RangeTableFunc")
        {
            return;
        }

        foreach (FieldDescriptor field in GetFields(node))
        {
            if (field.FieldType != FieldType.Message)
            {
                continue;
            }

            if (field.IsRepeated)
            {
                foreach (IMessage child in (System.Collections.IEnumerable)field.Accessor.GetValue(node))
                {
                    AddRangeBindings(child, bindings);
                }
            }
            else if (field.Accessor.HasValue(node) && field.Accessor.GetValue(node) is IMessage nestedItem)
            {
                AddRangeBindings(nestedItem, bindings);
            }
        }
    }

    private static string? GetAliasName(IMessage node, string aliasFieldName = "alias")
    {
        FieldDescriptor? aliasField = GetFields(node).FirstOrDefault(field =>
            field.JsonName == aliasFieldName &&
            field.FieldType == FieldType.Message &&
            field.Accessor.HasValue(node));
        if (aliasField?.Accessor.GetValue(node) is not IMessage alias)
        {
            return null;
        }

        return GetFields(alias).FirstOrDefault(static field => field.JsonName == "aliasname")
            ?.Accessor.GetValue(alias) as string;
    }

    private static int GetInt4ConstantProjectionCount(ParseResult parseResult)
    {
        if (parseResult.Stmts.Count != 1 ||
            parseResult.Stmts[0].Stmt?.SelectStmt is not SelectStmt select || select.TargetList.Count == 0 ||
            !parseResult.Stmts[0].Stmt.Equals(new Node { SelectStmt = select }))
        {
            return 0;
        }

        // Positive structural proof: every other SELECT field must be its parser default.
        // This excludes clauses, set operations, CTEs, subqueries and future unknown fields.
        SelectStmt remainder = select.Clone();
        remainder.TargetList.Clear();
        if (!remainder.Equals(new SelectStmt
        {
            Op = SetOperation.SetopNone,
            LimitOption = LimitOption.Default,
        }))
        {
            return 0;
        }

        foreach (Node node in select.TargetList)
        {
            if (node.ResTarget is not ResTarget target || target.Val?.AConst is not A_Const literal ||
                literal.Ival is null ||
                !node.Equals(new Node { ResTarget = target }) ||
                !target.Val.Equals(new Node { AConst = literal }) ||
                !target.Equals(new ResTarget { Name = target.Name, Location = target.Location, Val = target.Val }) ||
                !literal.Equals(new A_Const { Ival = literal.Ival, Location = literal.Location }) ||
                !literal.Ival.Equals(new PgSqlParser.Integer { Ival = literal.Ival.Ival }))
            {
                return 0;
            }
        }

        // The parser's integer node carries a signed 32-bit value: PostgreSQL assigns int4
        // directly, without input routines, typmods, or a pg_cast lookup.
        return select.TargetList.Count;
    }

    private static void CollectTypeReferences(
        IMessage node,
        HashSet<string> references,
        HashSet<string> risks)
    {
        if (node is FuncCall call && call.Funcname.Any(name =>
                TryGetStringLeaf(name, out string? part) && part is not null && part.Contains('.')))
        {
            // PostgreSQL also accepts type-name function syntax. A dotted delimited component
            // cannot be treated as lexical schema qualification for that conversion.
            risks.Add("unsupported_construct");
        }

        if (node is TypeName type)
        {
            List<string> parts = [];
            foreach (IMessage name in type.Names)
            {
                if (!TryGetStringLeaf(name, out string? part) || string.IsNullOrWhiteSpace(part))
                {
                    risks.Add("unsupported_construct");
                    return;
                }

                // Keep a delimited component from becoming a different qualified identifier.
                parts.Add(part.Contains('.') ? "\"" + part.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"" : part);
            }

            if (parts.Count is < 1 or > 2 || type.PctType || type.TypeOid != 0)
            {
                risks.Add("unsupported_construct");
            }
            else
            {
                references.Add(string.Join(".", parts) + (type.ArrayBounds.Count > 0 ? "[]" : ""));
            }
        }

        foreach (FieldDescriptor field in GetFields(node))
        {
            if (field.FieldType != FieldType.Message)
            {
                continue;
            }

            if (field.IsRepeated)
            {
                foreach (IMessage child in (System.Collections.IEnumerable)field.Accessor.GetValue(node))
                {
                    CollectTypeReferences(child, references, risks);
                }
            }
            else if (field.Accessor.HasValue(node) && field.Accessor.GetValue(node) is IMessage child)
            {
                CollectTypeReferences(child, references, risks);
            }
        }
    }

    private static bool ContainsSelectInto(IMessage node)
    {
        foreach (FieldDescriptor field in GetFields(node))
        {
            if (string.Equals(node.Descriptor.Name, "SelectStmt", StringComparison.Ordinal) &&
                string.Equals(field.JsonName, "intoClause", StringComparison.Ordinal) &&
                field.FieldType == FieldType.Message &&
                field.Accessor.HasValue(node))
            {
                return true;
            }

            if (field.IsRepeated)
            {
                if (field.FieldType != FieldType.Message)
                {
                    continue;
                }

                foreach (IMessage child in (System.Collections.IEnumerable)field.Accessor.GetValue(node))
                {
                    if (ContainsSelectInto(child))
                    {
                        return true;
                    }
                }
            }
            else if (field.FieldType == FieldType.Message &&
                     field.Accessor.HasValue(node) &&
                     field.Accessor.GetValue(node) is IMessage child &&
                     ContainsSelectInto(child))
            {
                return true;
            }
        }

        return false;
    }

    private static bool HasDirectPredicate(IMessage statement) =>
        GetFields(statement).Any(field =>
            string.Equals(field.JsonName, "whereClause", StringComparison.OrdinalIgnoreCase) &&
            field.FieldType == FieldType.Message &&
            field.Accessor.HasValue(statement));

    private static string MapStatementType(string protobufOneofName) =>
        protobufOneofName switch
        {
            "SelectStmt" => "Select",
            "InsertStmt" => "Insert",
            "UpdateStmt" => "Update",
            "DeleteStmt" => "Delete",
            "CreateStmt" => "CreateTable",
            "AlterTableStmt" => "AlterTable",
            "DropStmt" => "DropTable",
            "PrepareStmt" => "Prepare",
            "ExecuteStmt" => "Execute",
            "CopyStmt" => "Copy",
            _ => protobufOneofName,
        };

    private static void WalkMessage(
        IMessage node,
        string parentName,
        HashSet<string> columnsRead,
        HashSet<string> columnsWritten,
        HashSet<string> functions,
        HashSet<string> functionReferences,
        HashSet<string> operators,
        ref bool hasStar,
        ref bool hasNestedWrite)
    {
        // Visit actual statement messages at every depth, including modifying CTEs.
        CollectWriteTargetColumns(node, MapStatementType(node.Descriptor.Name), columnsWritten);
        bool nodeHasStar = string.Equals(parentName, "A_Star", StringComparison.OrdinalIgnoreCase);
        foreach (FieldDescriptor field in GetFields(node))
        {
            if (field.JsonName == "A_Star" && field.FieldType == FieldType.Message && field.Accessor.HasValue(node))
            {
                nodeHasStar = true;
            }

            if (field.JsonName == "funcname")
            {
                CollectFunctionField(node, field, functions, functionReferences);
            }
            if (IsOperatorNameField(node.Descriptor, field))
            {
                CollectOperatorField(node, field, operators);
            }
            if (node.Descriptor.Name == "JoinExpr" &&
                field.JsonName == "usingClause" &&
                field.IsRepeated && field.FieldType == FieldType.Message)
            {
                // JOIN USING reads every named key even if the projection omits it.
                foreach (IMessage key in (System.Collections.IEnumerable)field.Accessor.GetValue(node))
                {
                    CollectStringLeaf(key, columnsRead);
                }
            }

            bool nestedWriteStmt =
                field.JsonName is "InsertStmt" or "UpdateStmt" or "DeleteStmt" or "MergeStmt" &&
                field.FieldType == FieldType.Message &&
                field.Accessor.HasValue(node);
            if (nestedWriteStmt)
            {
                hasNestedWrite = true;
            }

            if (field.IsRepeated)
            {
                if (field.FieldType != FieldType.Message) continue;
                foreach (IMessage child in (System.Collections.IEnumerable)field.Accessor.GetValue(node))
                {
                    WalkMessage(child, field.JsonName, columnsRead, columnsWritten,
                        functions, functionReferences, operators, ref hasStar, ref hasNestedWrite);
                }
            }
            else if (field.FieldType == FieldType.Message && field.Accessor.HasValue(node) &&
                     field.Accessor.GetValue(node) is IMessage child)
            {
                WalkMessage(child, field.JsonName, columnsRead, columnsWritten,
                    functions, functionReferences, operators, ref hasStar, ref hasNestedWrite);
            }
        }

        if (nodeHasStar) hasStar = true;
        if (node is ColumnRef column && column.Fields.Count > 0)
        {
            // Only the final ColumnRef component names the column; preceding parts
            // qualify it with a range binding, schema or catalog. Collect by AST role,
            // not by suppressing alias names that may also be real columns elsewhere.
            // DML targets remain separate; projection stars still fail closed above.
            CollectStringLeaf(column.Fields[^1], columnsRead);
        }
    }

    private static void CollectFunctionField(IMessage node, FieldDescriptor field, HashSet<string> functions, HashSet<string> functionReferences)
    {
        List<string> parts = [];
        if (field.IsRepeated)
        {
            if (field.FieldType != FieldType.Message) return;
            foreach (IMessage child in (System.Collections.IEnumerable)field.Accessor.GetValue(node))
            {
                if (TryGetStringLeaf(child, out string? value) && value is not null)
                {
                    parts.Add(value);
                }
            }
        }
        else if (field.FieldType == FieldType.Message && field.Accessor.HasValue(node) &&
                 field.Accessor.GetValue(node) is IMessage child &&
                 TryGetStringLeaf(child, out string? value) &&
                 value is not null)
        {
            parts.Add(value);
        }

        if (parts.Count == 0)
        {
            return;
        }

        string reference = string.Join(".", parts);
        // These are parsed identifiers, including delimited "*" and whitespace names.
        // The generic string collector filters those values and would lose function calls.
        functionReferences.Add(reference);

        string function = parts.Count == 2
            && string.Equals(parts[0], "pg_catalog", StringComparison.Ordinal)
                ? parts[1]
                : reference;
        functions.Add(function);
    }

    private static void CollectWriteTargetColumns(
        IMessage statement,
        string statementType,
        HashSet<string> columnsWritten)
    {
        if (statementType == "Insert")
        {
            CollectResTargetList(statement, "cols", columnsWritten);

            FieldDescriptor? onConflictField = GetFields(statement).FirstOrDefault(field =>
                string.Equals(field.JsonName, "onConflictClause", StringComparison.Ordinal) &&
                field.FieldType == FieldType.Message &&
                field.Accessor.HasValue(statement));
            if (onConflictField?.Accessor.GetValue(statement) is IMessage onConflictClause)
            {
                CollectResTargetList(onConflictClause, "targetList", columnsWritten);
            }

            return;
        }

        if (statementType == "Update")
        {
            CollectResTargetList(statement, "targetList", columnsWritten);
        }
    }

    private static void CollectResTargetList(
        IMessage node,
        string fieldName,
        HashSet<string> columnsWritten)
    {
        FieldDescriptor? targetField = GetFields(node).FirstOrDefault(field =>
            string.Equals(field.JsonName, fieldName, StringComparison.Ordinal));
        if (targetField is null || !targetField.IsRepeated || targetField.FieldType != FieldType.Message)
        {
            return;
        }

        foreach (IMessage target in (System.Collections.IEnumerable)targetField.Accessor.GetValue(node))
        {
            CollectResTargetName(target, columnsWritten);
        }
    }

    private static bool CollectResTargetName(IMessage node, HashSet<string> columnsWritten)
    {
        if (string.Equals(node.Descriptor.Name, "ResTarget", StringComparison.Ordinal))
        {
            FieldDescriptor? nameField = GetFields(node).FirstOrDefault(field =>
                string.Equals(field.JsonName, "name", StringComparison.Ordinal) &&
                field.FieldType == FieldType.String);
            if (nameField?.Accessor.GetValue(node) is string name)
            {
                AddString(name, columnsWritten);
            }

            return true;
        }

        foreach (FieldDescriptor field in GetFields(node))
        {
            if (field.IsRepeated)
            {
                if (field.FieldType != FieldType.Message)
                {
                    continue;
                }

                foreach (IMessage child in (System.Collections.IEnumerable)field.Accessor.GetValue(node))
                {
                    if (CollectResTargetName(child, columnsWritten))
                    {
                        return true;
                    }
                }
            }
            else if (field.FieldType == FieldType.Message &&
                     field.Accessor.HasValue(node) &&
                     field.Accessor.GetValue(node) is IMessage child &&
                     CollectResTargetName(child, columnsWritten))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsOperatorNameField(MessageDescriptor descriptor, FieldDescriptor field) =>
        (string.Equals(descriptor.Name, "A_Expr", StringComparison.Ordinal) &&
         string.Equals(field.JsonName, "name", StringComparison.Ordinal)) ||
        (string.Equals(descriptor.Name, "SortBy", StringComparison.Ordinal) &&
         string.Equals(field.JsonName, "useOp", StringComparison.Ordinal)) ||
        (string.Equals(descriptor.Name, "SubLink", StringComparison.Ordinal) &&
         string.Equals(field.JsonName, "operName", StringComparison.Ordinal));

    private static void CollectOperatorField(IMessage node, FieldDescriptor field, HashSet<string> operators)
    {
        List<string> parts = [];
        if (field.IsRepeated)
        {
            if (field.FieldType != FieldType.Message) return;
            foreach (IMessage child in (System.Collections.IEnumerable)field.Accessor.GetValue(node))
            {
                if (TryGetStringLeaf(child, out string? value) && value is not null)
                {
                    parts.Add(value);
                }
            }
        }
        else if (field.FieldType == FieldType.Message && field.Accessor.HasValue(node) &&
                 field.Accessor.GetValue(node) is IMessage child &&
                 TryGetStringLeaf(child, out string? value) &&
                 value is not null)
        {
            parts.Add(value);
        }

        if (parts.Count > 0)
        {
            AddString(string.Join(".", parts), operators);
        }
    }

    private static bool TryGetStringLeaf(IMessage node, out string? value)
    {
        foreach (FieldDescriptor field in GetFields(node))
        {
            if (field.JsonName == "sval" && field.FieldType == FieldType.String &&
                field.Accessor.GetValue(node) is string direct)
            {
                value = direct;
                return true;
            }

            if (field.JsonName == "String" && field.Accessor.HasValue(node) &&
                field.Accessor.GetValue(node) is IMessage nested)
            {
                return TryGetStringLeaf(nested, out value);
            }
        }

        value = null;
        return false;
    }

    private static FieldDescriptor[] GetFields(IMessage node) =>
        DescriptorFields.GetOrAdd(node.Descriptor, descriptor => descriptor.Fields.InFieldNumberOrder().ToArray());

    private static void CollectStringLeaf(IMessage node, HashSet<string> sink)
    {
        foreach (FieldDescriptor field in GetFields(node))
        {
            if (field.JsonName == "sval" && field.FieldType == FieldType.String &&
                field.Accessor.GetValue(node) is string value)
            {
                AddString(value, sink);
            }
            else if (field.JsonName == "String" && field.Accessor.HasValue(node) &&
                     field.Accessor.GetValue(node) is IMessage nested)
            {
                AddDirectSval(nested, sink);
            }
        }
    }

    private static void AddDirectSval(IMessage node, HashSet<string> sink)
    {
        foreach (FieldDescriptor field in GetFields(node))
        {
            if (field.JsonName == "sval" && field.FieldType == FieldType.String && field.Accessor.GetValue(node) is string value)
            {
                AddString(value, sink);
            }
        }
    }

    private static void AddString(string value, HashSet<string> sink)
    {
        if (!string.IsNullOrWhiteSpace(value) && !string.Equals(value, "*", StringComparison.Ordinal)) sink.Add(value);
    }

}
