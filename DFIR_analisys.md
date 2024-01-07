## Introducción
En el paisaje digital contemporáneo, donde la ciberseguridad es una preocupación omnipresente, el DFIR (Digital Forensic and Incident Response) se erige como un pilar fundamental para abordar amenazas cibernéticas y salvaguardar la integridad de sistemas y datos. DFIR fusiona la forense digital y la respuesta a incidentes para ofrecer un enfoque holístico en la identificación, investigación y mitigación de incidentes de seguridad.

La forense digital, dentro del ámbito DFIR, se centra en la extracción, análisis y presentación de evidencia digital, permitiendo la reconstrucción de eventos, la identificación de amenazas y el respaldo de investigaciones legales. Por otro lado, la respuesta a incidentes se orienta a la detección temprana, contención y erradicación de amenazas, así como a la restauración de la normalidad operativa.

DFIR abarca una amplia gama de técnicas y herramientas, desde la adquisición de evidencia en dispositivos de almacenamiento hasta el análisis de registros de red y la mitigación de incidentes de seguridad. La capacidad para realizar análisis forenses de alta calidad y responder rápidamente a incidentes es esencial para minimizar el impacto de ataques cibernéticos y salvaguardar la continuidad del negocio.

En este contexto, la constante evolución de las amenazas cibernéticas exige que los profesionales de DFIR mantengan un conocimiento actualizado y estén equipados con habilidades avanzadas para enfrentar los desafíos emergentes.  En conjunto, la forense digital y la respuesta a incidentes se entrelazan para formar un enfoque integral que juega un papel crucial en la defensa cibernética y la preservación de la confianza en el entorno digital actual.

## Capture The Flag (CTF) DFIR
### HASH de la Muestra
- **Herramienta**: certuil - Windows System 
- **Captura**: 
1. Windows tiene una herramienta para calcular y verificar los hashes criptográficos la cual es **certuil**, una aplicación de línea de comandos instalada por defecto en el sistema.

2. Utilizando el comando `certuil -hashfile <DIR> SHA256` se obtuvo el hash **4446E9C42345A32FA78A8CE20834FAA047A3B161EBA986F894D2230FCF6B0CBE**

  
![Capture Hash](/img/.png)

### Nombre de la Máquina
- **Herramienta**: Registry Explorer - v1.6.0 - Eric Zimmerman 
- **Registro**: SYSTEM
- **Captura**: 
1. Se exporto de la muestra el registro **SYSTEM**.
2. Dentro del registro se accedio a la siguiente dirección: `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName` donde se recavo el nombre de la maquina **PEGASUS01**  
![Capture Computer Name](/img/pc_name.png)

## Ficheros Eliminados
- **Herramienta**: 
    Time Line Explorer - v1.3.0.0
    LogFile Parser 2.0.0.48  
- **Registro**: $LogFile
- **Captura**: 
1. Se extrajo el fichero $LogFile de la evidencia.
2. A traves de la herramienta LogFile Parser se obtuvo un fichero .csv el cual contenia los registros con acciones de ficheros del sistema.

![Capture LogFile ](/img/logparser.png)

3. El .csv generado contenia un gran cantidad de registros por lo que se hizo un filtrado usando un pequeño shell script con el cual filtramos los campos por el tipo de acción empleada y la extensión buscada (.zip).

**`(Get-Content .\LogFile.csv | Where-Object { $_ -match 'DeleteIndexEntryAllocation' -and $_ -match '.zip' })[1]`**

![Capture Computer Name](/img/pshell_filter.png)
### Contraseña del Usuario
- **Herramienta**: Mimikatz
- **Registros**: SYSTEM, SAM
- **Captura**:
1. Usando las muestras de los registros **SAM** y **SYSTEM** se obtuvieron los hash de las contraseñas de cada usuario del equipo.
2. Inicializando la herramienta **Mimikatz** se utilizo el siguiente comando para poder recavar el registro de contraseñas. 

    `lsadump::sam /system:C:\Users\forensic\Desktop\Evidence\Register\SYSTEM /sam:C:\Users\forensic\Desktop\Evidence\Register\SAM`
 
![Capture Passwords](/img/mimikatz_1.png)

3. Una vez con el registro se procedio a buscar al usuario **IEUser** del cual se tenian sospechas que pudo ser el medio por el cual el atacante accediera.

![Capture Passwords](/img/mimikatz_2.png)

4. Después de identificar el usuario y el hash asociado a la contraseña se utilizo la herramienta en línea **Crackstation** para decodificar el hash y obtener la contraseña.

![Capture Passwords](/img/crackstation.png)

## IP de Conexión RDP

## Análisis de Memoria RAM
### Introudcción
La memoria RAM, siendo el componente efímero y volátil de un sistema informático, juega un papel crucial en el ámbito de la forense digital y la respuesta a incidentes. La capacidad de extraer, analizar y comprender el contenido de la memoria RAM en un momento específico permite a los investigadores y profesionales de seguridad desentrañar el estado del sistema en ese instante, proporcionando valiosa información sobre las actividades recientes y potenciales amenazas.

La finalidad principal del análisis de memoria RAM radica en la identificación de artefactos digitales que podrían no estar presentes en otros medios de almacenamiento persistente. Desde contraseñas en texto claro hasta procesos ocultos, el análisis de la memoria RAM ofrece una ventana única para examinar la ejecución del sistema en tiempo real. Este proceso se ha vuelto esencial en la detección de intrusiones, la respuesta a incidentes y la reconstrucción de eventos, permitiendo a los investigadores abordar de manera efectiva la tarea de comprender las acciones previas de un sistema comprometido.

Este informe explorará la importancia del análisis de la memoria RAM, destacando su rol fundamental en la preservación de la integridad de la **cadena de custodia**, la identificación de malware persistente y la generación de evidencia digital sólida. A través de la aplicación de técnicas forenses avanzadas, el análisis de memoria RAM emerge como una herramienta esencial para la seguridad cibernética y la investigación forense en la era digital actual.

### Análisis Forense 
### 1. Adquisición
La adquisición de evidencia es el proceso crítico en la forense digital que involucra la recolección, preservación y aseguramiento de datos digitales con el objetivo de respaldar investigaciones legales. Este procedimiento asegura la integridad de la evidencia, garantizando que los datos recopilados sean auténticos y no hayan sido alterados. La adquisición se lleva a cabo utilizando herramientas y técnicas especializadas, abarcando desde la extracción de archivos y registros del sistema hasta la captura de volcados de memoria RAM.

Se corrio el siguiente comando para hacer la adquisición de la memoria utilizando la herramienta **winpmem**
```bash
winmpmem_mini_x64_rc2.exe w10_ram.mem
```
Esto nos generara el fichero w10_ram.mem ya partir de este se hizo el análisis siguiente.

### 2. Análisis de Procesos

El análisis de procesos en un volcado de memoria proporciona una visión profunda de la actividad del sistema operativo en un momento específico. Al examinar la jerarquía de procesos y sus atributos, los investigadores pueden identificar la ejecución de programas, entender las relaciones padre-hijo entre procesos y detectar posibles amenazas. Este análisis es crucial para rastrear la actividad del usuario, identificar procesos maliciosos o inusuales, y comprender cómo interactúan las aplicaciones en el sistema. La representación visual de un árbol de procesos facilita la identificación de procesos críticos y el seguimiento de la cadena de eventos en el sistema.

```bash
python3 vol.py -f "C:\Herramientas\01_Artefactos\RAM\w10_ram.mem" windows.pstree.PsTre
```
Volatility utiliza el plugin windows.pstree.PsTree para generar un árbol de procesos basado en el volcado de memoria RAM.

**`windows.pstree.PsTree`**: Hace referencia al plugin de Volatility utilizado. En este caso, **PsTree** se centra en la creación de una estructura de árbol que representa la jerarquía de procesos en el sistema.

El resultado de este comando será un árbol de procesos que representa la jerarquía de procesos en el sistema en el momento del volcado de memoria RAM. Cada nodo del árbol corresponde a un proceso.

- **Jerarquía de Procesos**: El árbol de procesos proporciona una visualización clara de la relación padre-hijo entre los procesos en el sistema. Cada nodo representa un proceso, y las conexiones indican la relación entre procesos padres e hijos.

- **Identificación de Procesos Principales**: Los procesos raíz o principales (sin proceso padre) son a menudo servicios del sistema o procesos esenciales. Observar estos nodos puede ser crucial para entender la estructura general del sistema.

- **Análisis de Conexiones**: Al revisar las conexiones entre procesos, se pueden identificar relaciones significativas o procesos que se originan de manera inusual.

- **Identificación de Procesos Relacionados**: La representación visual del árbol facilita la identificación de procesos relacionados y puede revelar actividades inusuales.

Este análisis de árbol de procesos es esencial para comprender la ejecución del sistema y puede ayudar a identificar procesos clave en la cadena de eventos. Analizar la jerarquía de procesos es particularmente útil para investigar incidentes, ya que **permite rastrear la relación entre procesos y comprender la estructura del sistema en el momento del volcado de memoria.**

```bash
python vol.py -f "C:\Herramientas\01_Artefactos\RAM\w10_ram.mem" windows.psscan.PsScan
```
**`windows.psscan.PsScan`**: Se refiere al plugin de Volatility que se está utilizando. En este caso, PsScan es específico para escanear y listar procesos en el volcado de memoria.

En el resultado se puede identificar los procesos en ejecución en el sistema al revisar la columna *"Name"*. Cada entrada representa un proceso específico.

**Relaciones Padre-Hijo**: Observa las columnas "PID" y "PPID" para entender las relaciones padre-hijo entre los procesos. El "PPID" indica el ID del proceso padre.

**Número de Hilos y Manejadores**: La información sobre el número de hilos y manejadores puede ser valiosa para comprender la complejidad y el comportamiento de un proceso.

**Anomalías Potenciales**: Busca procesos inusuales, conexiones anómalas o la presencia de procesos conocidos por ser maliciosos.

- **Procesos con Nombres Ofuscados**:
    Procesos que intentan ocultar su identidad mediante nombres de archivo y ejecutables ofuscados o con caracteres extraños.

- **Procesos en Ubicaciones Inusuales**:
    Procesos que se ejecutan desde ubicaciones no estándar o inusuales en el sistema de archivos, como directorios temporales.

- **Procesos sin Firma Digital o Firma No Confiada**:
    Procesos que no tienen una firma digital válida o cuya firma no es reconocida como confiable.

- **Procesos con Niveles Altos de Privilegios**:
    Procesos que se ejecutan con niveles elevados de privilegios sin una razón aparente o que están asociados con cuentas de usuario no autorizadas.

- **Procesos que Intentan Ocultarse**:
    Procesos que intentan ocultarse utilizando técnicas de rootkit u otras técnicas de evasión de detección.

- **Procesos con Comportamiento Anómalo**:
    Procesos que muestran comportamientos inusuales, como el consumo extremo de recursos, intentos frecuentes de comunicación en red o acceso a archivos críticos del sistema.

- **Procesos con Nombres que se Asemejan a Software Malicioso Conocido**:
    Procesos que tienen nombres similares a software malicioso conocido o que están asociados con amenazas específicas.

- **Procesos que No Tienen Correspondencia con el Sistema Operativo**:
Procesos que no tienen correspondencia con la lista de procesos esperados para el sistema operativo y la versión específicos.

Este análisis inicial de procesos mediante **windows.psscan.PsScan** es un paso fundamental para comprender la actividad del sistema en el momento del volcado de memoria.

### 3. Procesos de línea de comandos 

El análisis de líneas de comandos en un volcado de memoria revela las instrucciones exactas que se ejecutaron en el sistema. Examinar las líneas de comandos asociadas con cada proceso es crucial para entender las acciones específicas realizadas en el sistema, como la ejecución de programas, la manipulación de archivos y la interacción con servicios. Las líneas de comandos también son vitales para la identificación de actividades maliciosas o la presencia de herramientas no autorizadas. Este análisis proporciona una visión detallada de la interacción del usuario con el sistema y es esencial para la reconstrucción de eventos y la detección de amenazas que podrían haber dejado rastros en la memoria RAM.

Volatility utiliza el plugin **windows.cmdline.CmdLine** para extraer información relacionada con las líneas de comandos utilizadas por los procesos en el volcado de memoria RAM. A continuación, desglosaré los componentes clave de este comando y explicaré los resultados:
```bash
python3 vol.py -f "C:\Herramientas\01_Artefactos\RAM\w10_ram.mem" windows.cmdline.CmdLine
```
**`windows.cmdline.CmdLine`**: Se refiere al plugin de Volatility que se está utilizando. En este caso, CmdLine se enfoca en la recuperación de líneas de comandos utilizadas por los procesos.

El resultado de este comando proporcionará información sobre las líneas de comandos asociadas con los procesos en el volcado de memoria RAM. 

- **Identificación de Procesos**: La combinación de PID y el nombre del proceso te permitirá asociar la línea de comandos con un proceso específico.

- **Análisis de Actividades**: Al revisar las líneas de comandos utilizadas por los procesos, puedes obtener información sobre las acciones realizadas en el sistema. Esto puede incluir ejecución de programas, argumentos utilizados, y otros detalles.

- **Detección de Actividades Anómalas**: Busca líneas de comandos inusuales o no esperadas que puedan indicar actividades maliciosas o comportamientos anómalos.

Por ejemplo, si encuentras líneas de comandos que ejecutan programas desconocidos o que parecen ser herramientas de hacking, podría indicar actividades sospechosas que requieren una mayor investigación.

### 3. Análisis de Servicios
El análisis de servicios en un volcado de memoria es una práctica esencial en la investigación forense y la respuesta a incidentes. Los servicios del sistema operativo desempeñan un papel crítico en la funcionalidad y estabilidad del sistema, y su análisis proporciona una visión detallada de las actividades en el sistema. Al examinar los servicios presentes en el volcado de memoria, los investigadores pueden identificar servicios críticos, evaluar su estado de ejecución y buscar posibles indicadores de compromiso. Cambios inesperados en el estado de los servicios, la presencia de servicios desconocidos o modificaciones en la configuración son pistas clave que pueden señalar actividad maliciosa o anómala en el sistema.

Volatility utiliza el plugin **windows.svcscan.SvcScan** para analizar y extraer información sobre los servicios del sistema en el volcado de memoria RAM.

```bash
python3 vol.py -f "C:\Herramientas\01_Artefactos\RAM\w10_ram.mem" windows.svcscan.SvcScan
```

**`windows.svcscan.SvcScan`**: Hace referencia al plugin de Volatility utilizado. En este caso, SvcScan se centra en el análisis de servicios del sistema.

- **Identificación de Servicios Críticos**: Revisa la lista de servicios para identificar aquellos considerados críticos o esenciales para el funcionamiento del sistema operativo.

- **Estado del Servicio**: Examina el estado de cada servicio para identificar si está en ejecución, detenido u otro estado. **Cambios inesperados en el estado de un servicio pueden indicar actividad maliciosa.**

- **Análisis de Descripciones**: Las descripciones de los servicios pueden proporcionar información sobre la función y el propósito del servicio. Esto puede ser útil para determinar la relevancia y la normalidad de un servicio específico.

Este análisis de servicios es valioso para comprender la infraestructura del sistema y puede ayudar en la detección de cambios no autorizados, así como en la identificación de servicios que podrían estar asociados con actividades maliciosas. **El conocimiento de los servicios presentes en el sistema también es crucial para evaluar la integridad y la normalidad del entorno.**

## Análisis de Metadatos
### Introducción 
En la era digital contemporánea, la cantidad exponencial de datos generados diariamente ha posicionado a los metadatos como elementos cruciales para entender, organizar y gestionar la información. Esta parte del informe se centra en el análisis de metadatos en imagenes, revelando las complejidades subyacentes de los datos y proporcionando una visión profunda de su contexto y relevancia.
En este análisis se presenta la transformación de los metadatos al pasar por diversas plataformas.

### Origen
| Data Type  | Info |
|---|---|
File Name                       | origin_img.jpeg
Directory                       | .
File Size                       | 738 kB
File Modification Date/Time     | 2023:12:28 14:07:14-05:00
File Access Date/Time           | 2023:12:28 14:11:59-05:00
File Inode Change Date/Time     | 2023:12:28 14:11:59-05:00
File Permissions                | -rw-r--r--
File Type                       | JPEG
File Type Extension             | jpg
MIME Type                       | image/jpeg
Exif Byte Order                 | Big-endian (Motorola, MM)
Make                            | Xiaomi
Camera Model Name               | 2109119DG
Orientation                     | Rotate 270 CW
X Resolution                    | 72
Y Resolution                    | 72
Resolution Unit                 | inches
Modify Date                     | 2023:12:26 13:15:54
Y Cb Cr Positioning             | Centered
Exposure Time                   | 1/33
F Number                        | 2.2
Exposure Program                | Program AE
ISO                             | 184
Exif Version                    | 0220
Date/Time Original              | 2023:12:26 13:15:54
Create Date                     | 2023:12:26 13:15:54
Offset Time                     | -06:00
Offset Time Original            | -06:00
Components Configuration        | Y, Cb, Cr, -
Shutter Speed Value             | 1/33
Aperture Value                  | 2.2
Brightness Value                | 1.36
Exposure Compensation           | 0
Max Aperture Value              | 2.2
Metering Mode                   | Average
Light Source                    | D65
Flash                           | Off, Did not fire
Focal Length                    | 3.1 mm
Sub Sec Time                    | 559394
Sub Sec Time Original           | 559394
Sub Sec Time Digitized          | 559394
Flashpix Version                | 0100
Color Space                     | sRGB
Exif Image Width                | 2560
Exif Image Height               | 1440
Interoperability Index          | R98 - DCF basic file (sRGB)
Interoperability Version        | 0100
Sensing Method                  | Not defined
Scene Type                      | Directly photographed
Exposure Mode                   | Auto
White Balance                   | Auto
Focal Length In 35mm Format     | 26 mm
Scene Capture Type              | Standard
Compression                     | JPEG (old-style)
Thumbnail Offset                | 970
Thumbnail Length                | 16082
Image Width                     | 2560
Image Height                    | 1440
Encoding Process                | Baseline DCT, Huffman coding
Bits Per Sample                 | 8
Color Components                | 3
Y Cb Cr Sub Sampling            | YCbCr4:2:0 (2 2)
Aperture                        | 2.2
Image Size                      | 2560x1440
Megapixels                      | 3.7
Scale Factor To 35 mm Equivalent| 8.3
Shutter Speed                   | 1/33
Create Date                     | 2023:12:26 13:15:54.559394
Date/Time Original              | 2023:12:26 13:15:54.559394-06:00
Modify Date                     | 2023:12:26 13:15:54.559394-06:00
Thumbnail Image                 | (Binary data 16082 bytes, use -b option to extract)
Circle Of Confusion             | 0.004 mm
Field Of View                   | 69.4 deg
Focal Length                    | 3.1 mm (35 mm equivalent: 26.0 mm)
Hyperfocal Distance             | 1.21 m
Light Value                     | 6.5

### Mail
| Data Type  | Info |
|---|---|
|ExifTool Version Number | 12.67 |
| File Name  |  email_img.jpg  |
| Directory  |  . |
| File Size  |  142 kB   | 
File Modification Date/Time     | 2023:12:28 14:32:12-05:00
File Access Date/Time           | 2023:12:28 14:32:50-05:00
File Inode Change Date/Time     | 2023:12:28 14:32:50-05:00
File Permissions                | -rw-r--r--
File Type                       | JPEG
File Type Extension             | jpg
MIME Type                       | image/jpeg
JFIF Version                    | 1.01
Resolution Unit                 | None
X Resolution                    | 1
Y Resolution                    | 1
Image Width                     | 900
Image Height                    | 1600
Encoding Process                | Progressive DCT, Huffman coding
Bits Per Sample                 | 8
Color Components                | 3
Y Cb Cr Sub Sampling            | YCbCr4:2:0 (2 2)
Image Size                      | 900x1600
Megapixels                      | 1.4

#### Observaciones
La resolución y el tamaño de la imagen enviada por correo electrónico son considerablemente más bajos que los de la imagen original.

La información detallada de la cámara y los ajustes de exposición no se proporcionan en la imagen enviada por correo electrónico, lo cual es común ya que muchas plataformas eliminan esta información por motivos de privacidad.

### WhatsApp
| Data Type  | Info |
|---|---|
ExifTool Version Number         | 12.67
File Name                       | wats_img.jpg
Directory                       | .
File Size                       | 142 kB
File Modification Date/Time     | 2023:12:28 14:23:34-05:00
File Access Date/Time           | 2023:12:28 14:24:14-05:00
File Inode Change Date/Time     | 2023:12:28 14:24:14-05:00
File Permissions                | -rw-r--r--
File Type                       | JPEG
File Type Extension             | jpg
MIME Type                       | image/jpeg
JFIF Version                    | 1.01
Resolution Unit                 | None
X Resolution                    | 1
Y Resolution                    | 1
Image Width                     | 900
Image Height                    | 1600
Encoding Process                | Progressive DCT, Huffman coding
Bits Per Sample                 | 8
Color Components                | 3
Y Cb Cr Sub Sampling            | YCbCr4:2:0 (2 2)
Image Size                      | 900x1600
Megapixels                      | 1.4

#### Observaciones
Similar a la versión de correo electrónico, la imagen enviada a través de WhatsApp tiene una resolución y tamaño más bajos en comparación con la imagen original.

La información detallada de la cámara y los ajustes de exposición no se proporciona en la imagen enviada por WhatsApp, lo cual es consistente con la práctica común de eliminar estos metadatos por razones de privacidad y para reducir el tamaño del archivo.


### Telegram
| Data Type  | Info |
|---|---|
ExifTool Version Number         | 12.67 |
File Name                       | telegram_img.jpg |
Directory                       | . |
File Size                       |2023:12:28 14:28:11-05:00|
File Access Date/Time           |2023:12:28 14:29:07-05:00|
File Inode Change Date/Time     |2023:12:28 14:29:07-05:00♫
File Permissions                | -rw-r--r--
File Type                       | JPEG
File Type Extension             | jpg
MIME Type                       | image/jpeg
JFIF Version                    | 1.01
Resolution Unit                 | inches
X Resolution                    | 72
Y Resolution                    | 72
Profile CMM Type                | 
Profile Version                 | 2.1.0
Profile Class                   | Display Device Profile
Color Space Data                | RGB
Profile Connection Space        | XYZ
Profile Date Time               | 0000:00:00 00:00:00
Profile File Signature          | acsp
Primary Platform                | Unknown ()
CMM Flags                       | Not Embedded, Independent
Device Manufacturer             | 
Device Model                    | 
Device Attributes               | Reflective, Glossy, Positive, Color|
Rendering Intent                | Media-Relative Colorimetric
Connection Space Illuminant     | 0.9642 1 0.82491
Profile Creator                 | 
Profile ID                      | 0
Profile Description             | sRGB
Red Matrix Column               | 0.43607 0.22249 0.01392
Green Matrix Column             | 0.38515 0.71687 0.09708
Blue Matrix Column              | 0.14307 0.06061 0.7141
Red Tone Reproduction Curve     | (Binary data 40 bytes, use -b option to extract)
Green Tone Reproduction Curve   | (Binary data 40 bytes, use -b option to extract)
Blue Tone Reproduction Curve    | (Binary data 40 bytes, use -b option to extract)
Media White Point               | 0.9642 1 0.82491
Profile Copyright               | Google Inc. 2016
Image Width                     | 720
Image Height                    | 1280
Encoding Process                | Progressive DCT, Huffman codin|
Bits Per Sample                 | 8
Color Components                | 3
Y Cb Cr Sub Sampling            | YCbCr4:2:0 (2 2)
Image Size                      | 720x1280
Megapixels                      | 0.922

#### Observaciones
Similar a las versiones de correo electrónico y WhatsApp, la imagen enviada a través de Telegram tiene una resolución y tamaño más bajos en comparación con la imagen original.

A diferencia de WhatsApp, Telegram proporciona información adicional sobre el perfil de color y características de la imagen. Sin embargo, sigue sin incluir detalles de la cámara y los ajustes de exposición.

**NOTA**:*La información adicional sobre el perfil de color en Telegram es específica de la plataforma y puede no ser relevante para la información original de la imagen.*