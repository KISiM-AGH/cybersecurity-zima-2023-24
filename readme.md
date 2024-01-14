# Raport podatności znalezionych w aplikacji Webowej

Raport został przygotowany na potrzeby przedmiotu **Bezpieczeństwo Aplikacji Internetowych**.

Wykonali:
- Wioletta Drąg
- Stanisław Marek
- Aleksander Kuliński

### poziomy podatności
- [CRITICAL] - podatność krytyczna, która może doprowadzić do całkowitego przejęcia aplikacji.
- [HIGH] - podatność wysokiego poziomu, która może doprowadzić do przejęcia aplikacji.
- [MEDIUM] - podatność średniego poziomu, która może doprowadzić do przejęcia konta użytkownika.
- [LOW] - podatność niskiego poziomu, która może doprowadzić do przejęcia konta użytkownika.
- [INFO] - podatność informacyjna, która może doprowadzić do ujawnienia informacji.
  
## Podsumowanie wykonanych prac
## Wnioski
## Zalecenia
## Opis aplikacji
## Znalezione podatności
### SQL Injection

**[CRITICAL]**
```js
function do_auth(username, password) {
    var db = pgp(config.db.connectionString);

    var q = "SELECT * FROM users WHERE name = '" + username + "' AND password ='" + password + "';";

    return db.one(q);
}
```
Ten fragment kodu to funkcja do uwierzytelniania, przyjmuje nazwę użytkownika i hasło.
Wykorzystuje bibliotekę pg-promise (v: 4.4.6 **DEPRECATED**) do obsługi połączenia z bazą.
Sposób, w jaki są łączone są nazwa użytkownika i hasło do zapytania, jest podatny na ataki SQL Injection.

Zabezpieczenie przed atakami SQL Injection:
- Używanie parametryzowanych zapytań.
- Używanie bibliotek, które automatycznie zabezpieczają przed atakami SQL Injection.
- Filtracja i walidacja danych wprowadzanych przez użytkownika.

### Broken Authentication and Session Management

**[HIGH]**
```js
// Do auth
router.post('/login/auth', function(req, res) {

    var user = req.body.username;
    var password = req.body.password;
    var returnurl = req.body.returnurl;

    logger.error("Tried to login attempt from user = " + user);

    auth(user, password)
        .then(function (data) {
            req.session.logged = true;
            req.session.user_name = user;

            if (returnurl == undefined || returnurl == ""){
                returnurl = "/";
            }

            res.redirect(returnurl);
        })
        .catch(function (err) {
            res.redirect("/login?returnurl=" + returnurl + "&error=" + err.message);
        });

});
```
Ten fragment kodu to funkcja do uwierzytelniania, przyjmuje nazwę użytkownika, hasło i adres powrotu.
Sesja utrzymana jest za pomocą flagi **logged** i nazwy użytkownika **user_name**.

Potencjalne problemy wynikające z takiego mechanizmu uwierzytelniania:
- Brak możliwości ustawienia czasu wygaśnięcia sesji - sesja pozostanie aktywna do momentu wylogowania się użytkownika.
- Brak zabezpieczeń przed atakami typu brute-force - nie ma limitu prób logowania.
- Komunikat zwracany przy błędnym logowaniu to bezpośrednie wypisanie błędu zwróconego przez bazę danych. Mogą dostarczyć one informacji na temat struktury bazy danych, co może ułatwić atakującemu zadanie w przypadku próby przejęcia bazy danych.

### Dane logowania do bazy danych w kodzie źródłowym

**[HIGH]**
```yaml
version: '3.9'
services:
  vulnerable_node:
    restart: always
    build: .
    depends_on:
      - postgres_db
    ports:
      - "3000:3000"

  postgres_db:
    restart: always
    build: ./services/postgresql
    ports:
      - "5432:5432"
    environment:
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=postgres
```
W pliku docker-compose.yml znajdują się dane logowania do bazy danych.

Powinny być one przechowywane w zmiennych środowiskowych, najlepiej w pliku .env, który nie jest wersjonowany i/lub w repozytorium. 
### XSS - Cross Site Scripting

**[HIGH]**
#### JavaScript
```js
// Login template
router.get('/login', function(req, res, next) {

    var url_params = url.parse(req.url, true).query;

    res.render('login', {returnurl: url_params.returnurl, auth_error: url_params.error});
});
```
#### HTML
```html
...
<% if (auth_error != undefined) { %>
    <span class="label label-danger"><%-auth_error%></span>
<% } %>
...
```
Ten fragment kodu to funkcja renderująca szablon logowania.
Wartość parametru **error** jest wstawiana bezpośrednio do kodu HTML, co może doprowadzić do ataku XSS.

Przykładowe sposoby wykorzystania:
- Wykradanie ciasteczek sesji - czyli de facto przejęcie sesji użytkownika.
- Uruchomienie keyloggera - czyli przechwycenie wpisywanych danych.
- Przekierowanie na stronę phishingową - czyli przechwycenie danych logowania.
- Hostowanie malware - czyli zainfekowanie komputera użytkownika.

Jak zabezpieczyć się przed atakami XSS?
- Wszystkie dane wprowadzane przez użytkownika powinny być filtrowane i/lub walidowane.
- Wszystkie dane wyświetlane użytkownikowi powinny być filtrowane.
- Zastosowanie HttpOnly flag dla ciasteczek sesji. W ten sposób ciasteczka nie będą dostępne dla JavaScriptu.
  
### Konfiguracja cookies

**[HIGH]**
```js
app.use(session({
  secret: 'ñasddfilhpaf78h78032h780g780fg780asg780dsbovncubuyvqy',
  cookie: {
    secure: false,
    maxAge: 99999999999
  }
}));
```

W konfiguracji ciasteczek sesji znajdują się następujące problemy:
- Brak HttpOnly flagi - ciasteczka są dostępne dla JavaScriptu.
- Brak flagi secure - ciasteczka są wysyłane przez protokół HTTP, co może doprowadzić do ich przechwycenia.
- Bardzo długi czas wygaśnięcia ciasteczek sesji - sesja pozostanie aktywna do momentu wylogowania się użytkownika.
- Sekret sesji zaszyty jest w kodzie źródłowym aplikacji - powinien być przechowywany w zmiennych środowiskowych, najlepiej w pliku .env, który nie jest wersjonowany i/lub w repozytorium.