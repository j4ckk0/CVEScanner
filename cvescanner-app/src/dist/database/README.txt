Put the vulnerability database zip files in this folder WITHOUT extracting them.
Every .zip here is loaded when the program starts.

  advisory-database-main.zip                  GitHub Advisory Database (recommended)
  YYYY-MM-DD_all_CVEs_at_midnight.zip.zip     CVE List (optional)
  Maven-all.zip, npm-all.zip, PyPI-all.zip    OSV.dev exports (optional)
  nvdcve-2.0-YYYY.json.zip                    NVD CVE feeds, for components off-the-shelf (one a year,
  nvdcve-2.0-modified.json.zip                and the modified one)

To download them, on a computer with internet access: ../download-databases.sh (Linux) or
..\download-databases.bat (Windows), which asks first; or by hand, see ../README.md, "The databases".
When you update by hand, delete the old zip files.

Placez ici les fichiers zip des bases de vulnérabilités, SANS les extraire : chaque .zip de ce dossier est chargé au
démarrage. Pour les télécharger, sur un ordinateur relié à internet : ../download-databases.sh (Linux) ou
..\download-databases.bat (Windows), qui demande d'abord ; ou à la main, voir ../README.md, « The databases ».
