**Run Program:**

git clone https://github.com/maryclareleonard/secureSoftwareEngineering
python answer.py [xml file]

**Design Decisions:**

pom1.xml and pom2.xml were given. 
I did not end up figuring out how to do the string checking given the levenstein distance. I looked at the resources and understand what it would theoretically do, however implementing this in connection to querying the database was harder to unpack.

Instead to show that my program works as anticipated I created pom3.xml to pom6.xml.
All deal with vendor westerndigital product my_cloud.
The versions are changed slightly to show bounds. For the corresponding vulnerability the versions are 3.0.0 (inclusive) to 5.19.117 (non-inclusive). 

pom3.xml has a version below 3.0.0      [not vulnerability]

pom4.xml has version at 3.0.0           [vulnerability]

pom5.xml has version below 5.19.117     [vulnerability]

pom6.xml has version at 5.19.117        [not vulnerability]


As we discussed I only implemented this with the 2022 data feed instead of all of them for the sake of understanding how to interact with the NVD data feeds. 

**Output:**
Vendor: [vendor name]

Product: [product name]

Version: [version]

The bounds [start version ] to [end version]

The last two lines detail whether or not the Start or End Versions are included in the bounds.

**Note:**
I did not include a requirements.txt file as I do not have any external dependencies.
