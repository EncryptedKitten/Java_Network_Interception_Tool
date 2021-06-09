import zipfile, subprocess, pathlib, glob, os, shutil, configparser, sys

config = configparser.ConfigParser()
config.read("build.ini")

libs = glob.glob(config["GLOBAL"]["lib_dir"] + "/*.jar")
manifold = glob.glob(config["GLOBAL"]["manifold_dir"] + "/*.jar")
java_home = config["GLOBAL"]["java_home"]
preprocessor_dir = config["GLOBAL"]["preprocessor_dir"]

def clean_begin():
	for x in [config["GLOBAL"]["preprocessor_dir"], config["GLOBAL"]["class_dir"], config["GLOBAL"]["jar_dir"]]:
		if os.path.isdir(x):
			shutil.rmtree(x)

def clean_end():
	for x in [config["GLOBAL"]["preprocessor_dir"], config["GLOBAL"]["class_dir"]]:
		if os.path.isdir(x):
			shutil.rmtree(x)

def preprocessor(name):
	javafiles = glob.glob(config["GLOBAL"]["src_dir"] + "/**/*.java", recursive=True)
	javafiles += glob.glob(config["GLOBAL"]["src_dir"] + "/**/manifest.txt", recursive=True)

	orig_name = config["GLOBAL"]["src_name"]

	for javafile in javafiles:
		new_javafile = javafile.replace(config["GLOBAL"]["src_dir"], preprocessor_dir).replace(orig_name.replace(".", "/"), name.replace(".", "/"))
		pathlib.Path(os.path.dirname(new_javafile)).mkdir(parents=True, exist_ok=True)

		f = open(javafile)
		fcon = f.read()
		f.close()

		if (os.path.basename(javafile)) == "manifest.txt":
			fcon = fcon.replace(orig_name, name)
		
		else:
			for key, value in dict(config.items(name)).items():
				if (key.startswith("d.")):
					fcon = fcon.replace(key.split(".")[1].upper(), value)
			
			fcon = fcon.replace("package " + orig_name, "package " + name)
			fcon = fcon.replace("import " + orig_name, "import " + name)

		f = open(new_javafile, "w")
		f.write(fcon)
		f.close()


def build(name):
	pathlib.Path(config["GLOBAL"]["class_dir"]).mkdir(parents=True, exist_ok=True)

	javafiles = glob.glob(preprocessor_dir + "/**/*.java", recursive=True)

	classpath_string = ""

	classpaths = libs + manifold

	for classpath in classpaths[:-1]:
		classpath_string += classpath + ":"
	classpath_string += classpaths[-1]

	akeys = []

	for key, value in dict(config.items(name)).items():
		if (key.startswith("a.")):
			akeys.append("-A" + key.split(".")[1].upper() + "=" + value)

	subprocess.call([java_home + "/bin/javac"] + akeys + ["-classpath", classpath_string, "-Xplugin:Manifold", "-d", config["GLOBAL"]["class_dir"]] + javafiles)

def jar(name):
	pathlib.Path(config["GLOBAL"]["jar_dir"]).mkdir(parents=True, exist_ok=True)

	cwd = os.getcwd()
	newdir = config["GLOBAL"]["class_dir"]
	os.chdir(newdir)
	local_path_offset = "../" * len(newdir.split("/"))

	subprocess.call([java_home + "/bin/jar", "cmf", local_path_offset + preprocessor_dir + "/" + name.replace(".", "/") + "/manifest.txt",  local_path_offset + config["GLOBAL"]["jar_dir"] + "/" + config[name]["jar_name"] + "-" + config[name]["version"] + ".jar", name.replace(".", "/")])

	os.chdir(cwd)

def repack(name):
	zf = zipfile.ZipFile("build/jar/" + config[name]["jar_name"] + "-" + config[name]["version"] + ".jar", 'a')

	zf.write("README.md")
	zf.write("LICENSE.txt")

	for lib in libs:
		lib_zf = zipfile.ZipFile(lib, 'a')

		for lib_zf_item in lib_zf.infolist():
			if not lib_zf_item.filename.startswith("META-INF") and lib_zf_item.filename not in zf.namelist() and "/" in lib_zf_item.filename:
				zf.writestr(lib_zf_item, lib_zf.read(lib_zf_item))
		
		lib_zf.close()

def option(name):
	cwd = os.getcwd()

	preprocessor(name)
	build(name)
	jar(name)
	repack(name)

	os.chdir(cwd)

	if config["GLOBAL"]["clean_post_build"] == "true":
		clean_end()

def main():
	if config["GLOBAL"]["clean_pre_build"] == "true":
		clean_begin()

	if (len(sys.argv) == 1):
		config_sections = dict(config).keys()

		for build in config_sections:
			if build not in ["GLOBAL", "DEFAULT"] and config[build]["build"] == "true":
				print("Building " + build, end="")
				option(build)
				print(" - Done")
	else:
		for build in sys.argv[1:]:
			if build not in ["GLOBAL", "DEFAULT"]:
				print("Building " + build, end="")
				option(build)
				print(" - Done")

if __name__ == "__main__":
	main()