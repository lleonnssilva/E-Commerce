using Ocelot.Cache.CacheManager;
using Ocelot.DependencyInjection;
using Ocelot.Middleware;
using E_Commerce.UserManager;

var builder = WebApplication.CreateBuilder(args);
builder.Configuration.AddJsonFile("ocelot.json", optional: false,
                                   reloadOnChange: true);

// Add services to the container.
builder.Services.AddOcelot(builder.Configuration);
    //.AddCacheManager(x =>
    //{
    //    x.WithDictionaryHandle();
    //});


builder.Services.AddControllers();
builder.Services.AddJwtAutentication();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();


var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

await app.UseOcelot();

app.Run();