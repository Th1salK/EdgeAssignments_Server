using AutoMapper;
using EdgeAssignments.API.Dtos.Get;
using EdgeAssignments.API.Dtos.Post;
using EdgeAssignments.Core.Domain.Storage;
using EdgeAssignments.Core.Domain.Storage.Entities;
using EdgeAssignments.Core.Domain.Common.Repositories;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.JsonPatch;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.OData.Formatter;
using Microsoft.AspNetCore.OData.Query;
using Microsoft.AspNetCore.OData.Query.Wrapper;
using Microsoft.AspNetCore.OData.Routing.Controllers;
using SimplePatch;
using System.Web;

namespace EdgeAssignments.API.Controllers
{
    public class BaseController<E, R, W> : ODataController where E : BaseEntity, new() where R : BaseGetDto, new() where W : BasePostDto, new()
    {
        private readonly IBaseRepository<E> entityRepo;
        private readonly IMapper mapper;
        private readonly ILogger<E> logger;

        public BaseController(IBaseRepository<E> entityRepo, IMapper mapper, ILogger<E> _logger)
        {
            this.entityRepo = entityRepo;
            this.mapper = mapper;
            logger = _logger;
        }

        [HttpGet("search")]
        public async Task<ActionResult<R>> TextSearch(string searchText, string searchFields)
        {
            var searchFieldsList = HttpUtility.UrlDecode(searchFields).Split(",").ToList();
            var res = await entityRepo.TextSearchAsync(searchText, searchFieldsList);
            var response = mapper.Map<List<R>>(res);
            return Ok(response);
        }
        [HttpGet("{id}")]
        public virtual async Task<IActionResult> GetSingle(Guid id)
        {
            var result = await entityRepo.GetByIdAsync(id);
            if (result == null)
            {
                return NotFound();
            }
            var mappedResult = mapper.Map<R>(result);
            return Ok(mappedResult);
        }
        
        [HttpGet]
        [EnableQuery(MaxAnyAllExpressionDepth =20, MaxNodeCount =300)]
        public virtual async Task<ActionResult<List<R>>> Get(ODataQueryOptions<R> oDataQueryOptions)
        {
            // var searchText = oDataQueryOptions.Search?.RawValue;
            string? searchText = null;
            var cvList = new List<E>();
            if (searchText != null)
            {
                string typeName = typeof(E).Name;
                switch(typeName)
                {
                    case "Cv":
                        cvList = await entityRepo.TextSearchAsync(searchText, new List<string> {
                            "Profile.FirstName", 
                            "Profile.LastName", 
                            "Profile.Email",
                            "Profile.ShortIntro",
                            "Profile.LongIntro",
                            "Industries",
                            "ExpAreas",
                            "ToolsAndMethods.ToolsWithScale.Name",
                            "Certificates.Name",
                            "Certificates.Provider",
                            "Educations.Name",
                            "Educations.Provider",
                            "Courses.Name",
                            "Courses.Provider",
                            "Languages.Name",
                            "Employments.Name",
                            "Engagements.Client",
                            "Engagements.Role",
                            "Engagements.Project",
                            "Engagements.ShortIntro",
                            "Engagements.LongIntro"


                        });

                        break;

                    default:
                        cvList = await entityRepo.GetAllAsync();
                        break;
                }

                    
            }
            else
            {
                cvList = await entityRepo.GetAllAsync();
            }
         
            var mappedResult = mapper.Map<List<R>>(cvList);
            return Ok(mappedResult);
        }

        [HttpPost]
        public virtual async Task<ActionResult<R>> Post(W data)
        {
            var userId = HttpContext.Request.Headers["X-UserId"].FirstOrDefault();

            var entity = mapper.Map<E>(data);
            entity.CreatedBy = userId;
            entity.LastUpdated = DateTime.Now;
            var res = await entityRepo.AddAsync(entity);
            var response = mapper.Map<R>(res);
            return Ok(response);
        }
        [HttpPut("{id}")]
        public virtual async Task<ActionResult<R>> Put(Guid id, W data)
        {
            var userId = HttpContext.Request.Headers["X-UserId"].FirstOrDefault();
            var entity = mapper.Map<E>(data);
            entity.Id = id;
            entity.UpdatedBy = userId;
            entity.LastUpdated = DateTime.Now;
            var res = await entityRepo.UpdateAsync(entity);
            var response = mapper.Map<R>(res);
            return Ok(response);
        }
        [HttpDelete("{id}")]
        public virtual async Task<ActionResult<R>> Delete(Guid id)
        {
            await entityRepo.DeleteAsync(id);
            return Ok();
        }

        [HttpPatch("{id}")]
        public virtual async Task<ActionResult<R>> Patch(Guid id, [FromBody] JsonPatchDocument<W> data)
        {

            var userId = HttpContext.Request.Headers["X-UserId"].FirstOrDefault();

            var entity = await entityRepo.GetByIdAsync(id);
            entity.UpdatedBy = userId;
            var mappedData = mapper.Map<W>(entity);
            // data.ApplyTo(mappedData, ModelState);
            data.ApplyTo(mappedData);
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var remapp = mapper.Map<E>(mappedData);

            remapp.LastUpdated = DateTime.Now;
            var res = await entityRepo.UpdateAsync(remapp);
            var response = mapper.Map<R>(res);
            return Ok(response);
        }

    }
}
