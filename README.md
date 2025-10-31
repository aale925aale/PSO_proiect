Ne-am propus sa implementam un server HTTP, care sa atinga urmatoarele functionalitati (pentru inceput, vor fi imbunatatite pe parcurs)
Vom avea un server care va gestiona cererile trimise de la 1 sau mai multi clienti.
SERVER:
  1. Asiguram o comunicare server-client, TCP/IP
  2. Posibilitatea conectarii mai multor clienti simultan (thread pool)
  3. Clientul poate trimite diferite tipuri de cereri catre server (GET,POST,PUT)
  4. Serverul executa cererile clientilor IN FUNCTIE DE PRIORITATEA LOR.
  5. Tratarea cazurilor in care o cerere nu exista (404...)
