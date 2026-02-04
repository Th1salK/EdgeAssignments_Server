namespace EdgeAssignments.Core.Domain.Storage.Entities;

using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

public abstract class BaseEntity
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string? Id { get; set; }
    public string? CreatedBy { get; set; }
    public string? UpdatedBy { get; set; }
    public DateTime? LastUpdated { get; set; }
}
