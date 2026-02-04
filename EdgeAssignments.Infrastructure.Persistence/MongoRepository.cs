using EdgeAssignments.Core.Domain.Common.Repositories;
using EdgeAssignments.Core.Domain.Storage.Configs;
using EdgeAssignments.Core.Domain.Storage.Entities;
using Microsoft.AspNetCore.Http;
using MongoDB.Bson;
using MongoDB.Driver;
using MongoDB.Driver.Linq;
using System.Linq.Expressions;

namespace EdgeAssignments.Infrastructure.Persistence
{
    public class MongoRepository<T> : IBaseRepository<T> where T : BaseEntity
    {
        protected readonly IMongoClient client;

        protected readonly IMongoCollection<T> Collection;
        protected readonly IMongoCollection<BsonDocument> bsonCollection;
        private readonly ApplicationSettings settings;

        public MongoRepository(ApplicationSettings settings, IHttpContextAccessor httpContentAccessor)
        {
            client = new MongoClient(settings.ConnectionString);
            var collectionName = typeof(T).Name;
            var tenant = httpContentAccessor?.HttpContext?.Request?.Headers["X-Tenant"].FirstOrDefault();

            if(tenant!=null)
            {
                Collection = client
                    .GetDatabase(tenant)
                    .GetCollection<T>(collectionName.ToLower());

                bsonCollection = client
                   .GetDatabase(tenant)
                   .GetCollection<BsonDocument>(collectionName.ToLower());
            }
            else
            {
                Collection = client
                    .GetDatabase(settings.DatabaseName)
                    .GetCollection<T>(collectionName.ToLower());

                bsonCollection = client
                   .GetDatabase(settings.DatabaseName)
                   .GetCollection<BsonDocument>(collectionName.ToLower());
            }
            
            this.settings = settings;
        }

        public async Task<List<T>> TextSearchAsync(string searchText, List<string> fieldsList)
        {
            var searchTextFilter = new List<FilterDefinition<T>>();
            foreach (var field in fieldsList)
            {
                searchTextFilter.Add(Builders<T>.Filter.Regex(field, new BsonRegularExpression(searchText, "i")));
            }
            var filter = Builders<T>.Filter.Or(searchTextFilter);
            return await Collection.Aggregate()
                .Match(filter)
                .ToListAsync();
        }

        public async Task<T> AddAsync(T obj)
        {

            var document = obj.ToBsonDocument();
            document["_id"] = ObjectId.Empty;
            await bsonCollection.InsertOneAsync(document);
            obj.Id = document["_id"].ToString();

            return obj;

        }

        public async Task<T> AddWithIdAsync(T obj)
        {
            var document = obj.ToBsonDocument();
            await bsonCollection.InsertOneAsync(document);
            obj.Id = document["_id"].ToString();
            return obj;
        }

        public async Task DeleteAsync(string id)
        {
            await Collection.DeleteOneAsync(x => x.Id == id);
        }

        public async Task DeleteAsync(Expression<Func<T, bool>> predicate)
        {
            await Collection.DeleteManyAsync(predicate);
        }

        public async Task<List<T>> GetAllAsync(string? tenant=null)
        {
            if(tenant!=null)
            {
                return await client.GetDatabase(tenant)
                    .GetCollection<T>(typeof(T).Name.ToLower())
                    .AsQueryable().ToListAsync();
            }
            else
            {
                return await Collection.AsQueryable().ToListAsync();
            }
           
        }

        public async Task<T> GetByIdAsync(string id)
        {
            return await Collection.Find(Builders<T>.Filter.Eq(x => x.Id, id))
                .SingleOrDefaultAsync();
        }

        public async Task<List<T>> GetByIdsAsync(List<string> id,string? tenant = null)
        {
            if(tenant!=null)
            {
                return await client.GetDatabase(tenant)
                    .GetCollection<T>(typeof(T).Name.ToLower())
                    .AsQueryable().Where(x => x.Id != null && id.Contains(x.Id)).ToListAsync();
            }
            else
            {
                return await Collection.AsQueryable().Where(x => x.Id != null && id.Contains(x.Id)).ToListAsync();
            }
         
        }


        public async Task PutAllAsync(IEnumerable<T> entities)
        {
            var filterBuilder = Builders<T>.Filter;
            var newItems = entities.Select(item => new ReplaceOneModel<T>(filterBuilder.Where(x => x.Id == item.Id), item));

            await Collection.BulkWriteAsync(newItems);
        }

        public async Task<List<T>> SearchAsync(Expression<Func<T, bool>> predicate, string? tenant = null)
        {
            if (tenant != null)
            {
                var result = await client.GetDatabase(tenant).GetCollection<T>(typeof(T).Name.ToLower()).FindAsync(predicate);
                return await result.ToListAsync();

            }
            else
            {

                var result = await Collection.FindAsync(predicate);
                return await result.ToListAsync();
            }
        }

        public async Task<T> UpdateAsync(T obj, Expression<Func<T, bool>>? predicate = null)
        {
            if (predicate == null)
            {
                predicate = (p) => p.Id == obj.Id;
            }
            await Collection.ReplaceOneAsync(predicate, obj);
            return obj;
        }

        public async Task AddAllAsync(IEnumerable<T> entities)
		{
			var documents = new List<BsonDocument>();

			foreach (var entity in entities)
			{
                // Generate a new ObjectId for every entity
                if (String.IsNullOrEmpty(entity.Id))
                {
                   var objectId = ObjectId.GenerateNewId();
                   entity.Id = objectId.ToString();
                }

				// Convert to BsonDocument and set the _id
				var doc = entity.ToBsonDocument();
				doc["_id"] = ObjectId.Parse(entity.Id);

				documents.Add(doc);
			}

			await bsonCollection.InsertManyAsync(documents);
		}

        public async Task UpdateAllAsync(IEnumerable<T> entities)
        {
            if (entities == null)
                return;

            var bulkOps = new List<WriteModel<T>>();

            foreach (var entity in entities)
            {
                if (string.IsNullOrEmpty(entity.Id))
                {
                    throw new ArgumentException("Entity Id cannot be null or empty for update.");
                }

                var doc = entity.ToBsonDocument();
                doc["_id"] = ObjectId.Parse(entity.Id);

                var filter = Builders<T>.Filter.Eq(e => e.Id, entity.Id);

                var replaceOp = new ReplaceOneModel<T>(filter, entity)
                {
                    IsUpsert = false // set true if you want to insert if not exists
                };

                bulkOps.Add(replaceOp);
            }

            if (bulkOps.Count > 0)
            {
                await Collection.BulkWriteAsync(bulkOps);
            }
        }


        public Task<int> CountAsync()
        {
            return Collection.AsQueryable().CountAsync();
        }


    }
}