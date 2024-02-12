using AuthJwt.Interfaces;
using AuthJwt.Models;
using AuthJwt.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();

builder.Services.TryAddScoped<SignInManager<AppUser>>();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c => {
    c.IncludeXmlComments("swaggeComments.xml");
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "Test01", Version = "v1" });

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme()
    {
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "JWT Authorization header using the Bearer scheme."

    });
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                          new OpenApiSecurityScheme
                          {
                              Reference = new OpenApiReference
                              {
                                  Type = ReferenceType.SecurityScheme,
                                  Id = "Bearer"
                              }
                          },
                         new string[] {}
                    }
                });

});
builder.Services.AddTransient<IJwt,JwtService> ();

builder.Services.AddDbContext<AuthDbContext>(op =>
{
    op.UseSqlServer(builder.Configuration.GetConnectionString("Default"));
    
});
/*****************************AddIdentity, It is useful when we work with identity cookie*********************************/

builder.Services.AddIdentity<AppUser, AppRole>(op =>
{
    op.Lockout.AllowedForNewUsers = true;
    op.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(1);
    op.Lockout.MaxFailedAccessAttempts = 5;
    op.User.RequireUniqueEmail = true;
    op.SignIn.RequireConfirmedEmail = true;
  
    

}).AddEntityFrameworkStores<AuthDbContext>().AddDefaultTokenProviders().
AddUserStore<UserStore<AppUser, AppRole, AuthDbContext, Guid>>().
AddRoleStore<RoleStore<AppRole, AuthDbContext, Guid>>();

/*****************************AddIdentityCore, It is useful when we work jwt token*********************************/
/*builder.Services.AddIdentityCore<AppUser>(op =>
{
    op.Password.RequiredLength = 10;

}).AddRoles<AppRole>().
AddRoleManager<RoleManager<AppRole>>()
.AddEntityFrameworkStores<AuthDbContext>();*/

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(op =>
{
    op.UseSecurityTokenValidators = true;
    op.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateAudience = true,
       ValidAudience = builder.Configuration.GetRequiredSection("Jwt")["Audience"],
        ValidateIssuer = true,
        ValidIssuer = builder.Configuration.GetRequiredSection("Jwt")["Issuer"],
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(builder.Configuration.GetRequiredSection("Jwt")["Key"]))
    };
});
builder.Services.AddAuthorization(op =>
{
    op.AddPolicy("UbaidPolicy", policy =>
    {
        policy.AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme);
        policy.RequireRole("superadmin");
        policy.RequireClaim("saKey1", "saVal1");
       
     
    });
    
    //we also can use RequireAssertion method for above role and claims logic.
    //In RequireAssertion we can write our own logic for authorization.
    op.AddPolicy("UbaidPolicy2", policy =>
    {
        policy.AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme);
        policy.RequireAssertion(context =>
        context.User.HasClaim(c => c.Type == "saKey1" && c.Value == "saVal1") &&
        context.User.IsInRole("superadmin")
        );
    });
});
var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c => c.InjectStylesheet("/swagger-ui/SwaggerDark.css")) ;
}

app.UseHsts();
app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();
