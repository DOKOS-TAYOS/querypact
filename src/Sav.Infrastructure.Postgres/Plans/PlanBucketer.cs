namespace Sav.Infrastructure.Postgres.Plans;

/// <summary>
/// Buckets raw planner total cost into closed vocabulary trivial|low|moderate|high|extreme.
/// </summary>
public static class PlanBucketer
{
    public static readonly string[] OrderedBuckets =
    [
        "trivial",
        "low",
        "moderate",
        "high",
        "extreme",
    ];

    public static string Bucketize(double totalCost)
    {
        if (totalCost < 10d)
        {
            return "trivial";
        }

        if (totalCost < 100d)
        {
            return "low";
        }

        if (totalCost < 1_000d)
        {
            return "moderate";
        }

        if (totalCost < 10_000d)
        {
            return "high";
        }

        return "extreme";
    }

    public static int Ordinal(string costBucket)
    {
        int index = Array.FindIndex(
            OrderedBuckets,
            b => string.Equals(b, costBucket, StringComparison.Ordinal));
        if (index < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(costBucket), costBucket, "Unknown cost bucket.");
        }

        return index;
    }
}
