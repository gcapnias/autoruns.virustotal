﻿### Autoruns.VirusTotal

Εφαρμογή για την γρήγορη επεξεργασία των αποτελεσμάτων του 'autorunsc.exe'

### Στα γρήγορα
Για την χρήση της εφαρμογής πρέπει να έχετε ένα κλειδί για το API του Virus Total. Μέσα από το profile του χρήστη στο Virus Total, μπορείτε να δείτε το κλειδί σας για τη χρήση του API.
Η εφαρμογή μπορεί να χρησιμοποιηθεί με δύο τρόπους:

1. Με ανακατεύθυνση των αποτελεσμάτων του autorunsc.exe   
```
PS C:> autorunsc -nobanner -s -c | autoruns.virustotal <VT API Key>
```
2. Με ενδιάμεσο αρχείο που παράγεται από το autorunc.exe
```
PS C:> autorunsc -nobanner -s -c > filelist.txt
PS C:> autoruns.virustotal <VT API Key> filelist.txt
```

### Δυνατότητες
Η εφαρμογή μπορεί να στείλει ένα αριθμό αρχείων που έχουν συλλεχθεί από το autorunsc.exe για ανάλυση στο Virus Total με χρήση του API του. Η εφαρμογή χρησιμοποιεί την έκδοση v2 του API, καθώς έτσι της επιτρέπεται, με ένα request προς το service, να λάβει αποτελέσματα για περισσότερα του 1 αρχείου. Η ίδια δυνατότητα δεν υπάρχει στην έκδοση v3 του API.

Τα αρχεία που επιλέγονται από την εφαρμογή, φιλτράρονται στην συνέχεια με τις enviroment variables, για να περάσουν προς το API μόνο αρχεία που, είτε βρίσκονται μέσα στο φάκελο προσωρινών αρχείων του συστήματος που εμφανίζει η **'TEMP'** enviroment variable, ή μέσα σε ένα από τους φακέλους που ειναι εγκατεστημένα τα Windows (enviroment variable **'WINDIR'**)

### Εγκατάσταση
Για την εκτέλεση της εφαρμογής απαιτείται η εγκατάσταση του **.NET Core v3.1 LTS SDK**. Οδηγίες για την εγκατάσταση του, μπορούν να βρεθούν στην σελίδα [Download .NET Core 3.1](https://dotnet.microsoft.com/en-us/download/dotnet/3.1).

Μετά την εγκτάσταση, πρέπει να γίνει clone το repository, και στη συνέχεια να γίνει το build της εφαρμογής. Ενδεικτικά:
```
PS C:> git clone https://github.com/gcapnias/autoruns.virustotal.git
PS C:> cd autoruns.virustotal
PS C:> dotnet build
```
