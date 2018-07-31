update:
	git commit -am "Makefile auto commit"
	git push
	go get -u -v "github.com/williamrhancock/ArmorCompliance"
	@echo "\n**Sync, commit, and push completed!**"
	
	
