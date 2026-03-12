# Reflektionsfrågor – Övning 15.3

## 1. Varför används BCrypt för lösenordshashing istället för SHA256 eller MD5?

SHA256 och MD5 är snabba hash-algoritmer — de är designade för att beräkna checksummor effektivt, inte för att skydda lösenord. Det gör dem sårbara för brute force- och rainbow table-attacker: en angripare kan testa miljarder kombinationer per sekund på modern hårdvara.

BCrypt är ett **lösenordsspecifikt** hashingalgoritm med tre viktiga egenskaper:
- **Kostnadsfaktor (work factor)**: BCrypt kör en intern nyckelexpansion upprepade gånger (2^cost iterationer). Det gör varje hash-beräkning avsiktligt långsam (t.ex. 100ms istället för nanosekunder). Kostnadsfaktorn kan höjas i takt med att hårdvara blir snabbare.
- **Inbyggt salt**: BCrypt genererar automatiskt ett slumpmässigt salt och bäddar in det i hash-strängen. Varje lösenord får alltså en unik hash, vilket gör rainbow tables verkningslösa.
- **Tidskonstant verifiering**: `BCrypt.Verify()` tar lika lång tid oavsett om lösenordet matchar eller inte, vilket skyddar mot timing-attacker.

---

## 2. Vad är token rotation och varför är det en säkerhetsförbättring?

Token rotation innebär att varje gång en refresh token används för att hämta en ny access token, **invalideras den gamla refresh token omedelbart** och en helt ny utfärdas i dess ställe.

**Säkerhetsvinsten**: Om en angripare lyckas stjäla en refresh token och försöker använda den *efter att den legitima användaren redan har roterat den*, kommer servern att känna igen att token inte längre är giltig och neka åtkomst. I system med **refresh token reuse detection** (utöver enkel rotation) kan servern dessutom detektera att en gammal token presenteras — ett tecken på att token läckt — och då invalidera *alla* sessioner för användaren som en säkerhetsåtgärd.

---

## 3. Din UserService lagrar data in-memory. Vad behöver ändras för att koppla till en riktig databas i moment 16?

Med Entity Framework Core och en riktig databas behöver följande ändras:

1. **DbContext**: Skapa en `AppDbContext : DbContext` med en `DbSet<User> Users`.
2. **Anslutningssträng**: Lägg till `ConnectionStrings:DefaultConnection` i `appsettings.json`.
3. **UserService**: Byt ut `List<User>` mot `AppDbContext`. Alla `FirstOrDefault`-anrop mot listan byts till LINQ-frågor mot `_context.Users` (med `await` och `ToListAsync`/`FirstOrDefaultAsync`).
4. **DI-registrering**: Lägg till `builder.Services.AddDbContext<AppDbContext>(...)` i `Program.cs`.
5. **Migrationer**: Kör `dotnet ef migrations add InitialCreate` och `dotnet ef database update` för att skapa databasschemat.

`IUserService`-interfacet och alla controllers förblir *oförändrade* — det är hela poängen med Dependency Injection och Interface Segregation.

---

## 4. Hur skyddar refresh token-systemet mot att en stulen access token används under lång tid?

Access tokens har avsiktligt **kort livslängd** (i detta projekt 60 minuter). En stulen access token kan alltså bara missbrukas under en begränsad tid. När den löper ut kan angriparen *inte* förnya den utan att också ha refresh token.

Refresh tokens lagras på serversidan och kan när som helst **invalideras vid logout** (`UpdateRefreshTokenAsync(id, null, null)`). Om en användare märker att kontot missbrukas kan de logga ut och omedelbart göra angriparens refresh token värdelöst — vilket i sin tur hindrar utfärdande av nya access tokens.

Systemet separerar alltså "bevisa att du är du" (refresh token, långlivad, lagras säkert) från "presentera vid varje API-anrop" (access token, kortlivad, kan cachas av klienten).

---

## 5. Vad är skillnaden mellan [Authorize] och [Authorize(Roles = "Admin")]?

| Attribut | Krav |
|---|---|
| `[Authorize]` | Användaren måste vara **autentiserad** — ha ett giltigt, icke-utgånget JWT. Roll spelar ingen roll. |
| `[Authorize(Roles = "Admin")]` | Användaren måste vara autentiserad **och** ha `role`-claimet satt till `"Admin"` i sin token. |

En inloggad användare med rollen `"User"` passerar `[Authorize]` men får **403 Forbidden** på en endpoint med `[Authorize(Roles = "Admin")]`. Det gör det möjligt att bygga upp rollbaserad åtkomstkontroll (RBAC) där t.ex. DELETE-endpoints kräver Admin-behörighet medan GET-endpoints är tillgängliga för alla inloggade användare.
