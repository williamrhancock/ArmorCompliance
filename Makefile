update:
	git commit -am "Makefile auto commit"
	git push
	go get -u -v "github.com/williamrhancock/ArmorCompliance"
	@echo "Commit, push, and go src update done!"
	
	
