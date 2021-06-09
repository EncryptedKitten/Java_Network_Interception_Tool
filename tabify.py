import glob, configparser, os

def fix(x):
	print(x)
	f = open(x)
	fcon = f.read()
	f.close()

	fcon = fcon.replace("	", "\t")
	fcon = fcon.replace("	", "\t")
	fcon = fcon.replace("\r", "")

	f = open(x, "w")
	f.write(fcon)
	f.close()

def main():
	config = configparser.ConfigParser()
	config.read("build.ini")

	files = glob.glob(config["GLOBAL"]["src_dir"] + "/**/*", recursive=True)
	files += glob.glob("*.txt")
	files += glob.glob("*.ini")
	files += glob.glob("*.md")
	files += glob.glob("*.py")
	files += glob.glob("*.sh")

	for x in files:
		if os.path.isfile(x):
			fix(x)


if __name__ == "__main__":
	main()