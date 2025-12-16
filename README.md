Ne-am propus sa implementam un server HTTP, care sa atinga urmatoarele functionalitati (pentru inceput, vor fi imbunatatite pe parcurs)
Vom avea un server care va gestiona cererile trimise de la 1 sau mai multi clienti.
SERVER:
  1. Asiguram o comunicare server-client, TCP/IP
  2. Posibilitatea conectarii mai multor clienti simultan (thread pool)
  3. Serverul gestioneaza diferitele tipuri de cereri ale clientilor (GET, POST, HEAD, OPTIONS).
  5. Serverul executa cererile clientilor IN FUNCTIE DE PRIORITATEA LOR (asignăm o prioritate în funcție de tipul de request = cozi de priorități).
  6. Tratarea cazurilor în care o cerere nu exista (404...) sau răspunsuri afirmative (200 - OK), în format HTTP.
  7. Salvarea datelor primite de la client în fișiere.
  8. Jurnalizarea activitatii pe server intr-un fisier de log-uri.

CLIENTUL:
  1. Clientul poate trimite diferite tipuri de cereri catre server (GET,POST,OPTIONS)
  2. Fiecare client care se conecteaza la server poate fi tratat separat, pt ca mai multi clienti sa poata folosi serverul in acelasi timp, fara sa se blocheze (procese / threaduri)
  3. Proprietatea de autentificare user
  4. Inerfata grafica pentru useri
