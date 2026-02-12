namespace EdgeAssignments.Core.Domain.Storage.Entities;

using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

public abstract class BaseEntity
{
    [BsonId]
    [BsonRepresentation(BsonType.String)]
    public Guid Id { get; set; } = Guid.NewGuid();
    public string? CreatedBy { get; set; }
    public string? UpdatedBy { get; set; }
    public DateTime? LastUpdated { get; set; }
}
