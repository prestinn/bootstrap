import xml.etree.ElementTree as ET
from time import gmtime, strftime
import glob
import os


# Sample nmap report to build upon
nmap_sample = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="bootstrap.xsl" type="text/xsl"?>
<nmaprun scanner="nmap" args="" start="1539300354" startstr="" version="7.70" xmloutputversion="1.04">
<scaninfo type="syn" protocol="tcp" numservices="1000"/>

<host>
</host>
</nmaprun>"""

# Some path finding and creating the sample.xml
root = ET.fromstring(nmap_sample)
tree = ET.ElementTree(root)
tree.write('modules/bootstrap/sample.xml')
file_path = os.path.dirname(os.path.abspath(__file__))
xmlfiles = glob.glob(file_path + "/../../**/xml/*.xml", recursive=True)

def find_child(node, with_name):
    for element in list(node):
        if element.tag == with_name:
            return element
        elif list(element):
            sub_result = find_child(element, with_name)
            if sub_result is not None:
                return sub_result
    return None

def insert_node(from_tree, to_tree, node_name):
    from_node = find_child(from_tree.getroot(), node_name)
    to_node = find_child(to_tree.getroot(), node_name)
    to_parent, to_index = get_node_parent_info(to_tree, to_node)
    
    if from_node is not None:
        to_parent.insert(to_index, from_node)

def get_node_parent_info(tree, node):
    parent_map = {c:p for p in tree.iter() for c in p}
    parent = parent_map[node]
    return parent, list(parent).index(node)


def create_bootstrap_report():
    for i in xmlfiles:
        try:
            print("[+] Adding XML file: {} to sample.xml".format(i))
            from_tree = ET.ElementTree(file=i)
            to_tree = ET.ElementTree(file='modules/bootstrap/sample.xml')
            insert_node(from_tree, to_tree, 'host')
            to_tree.write('modules/bootstrap/sample.xml')
        except Exception as e:
            print("[-] XML node fucked, probally no results: " + str(i))
            print("[*] Deleting the fucked up node!")
            os.remove(i)
            pass

if __name__ == "__main__":
    create_bootstrap_report()
