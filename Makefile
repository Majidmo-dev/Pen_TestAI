.PHONY: lab-up lab-down run eval verify-audit

lab-up:
	docker compose up -d --wait dvwa llm-proxy

lab-down:
	docker compose down -v

run: lab-up
	docker compose run --build --rm agent python main.py --target dvwa
	$(MAKE) lab-down

# The lab is managed here on the host: the agent container has no docker access.
eval: lab-up
	docker compose run --build --rm agent python eval.py --all --skip-setup; \
		status=$$?; $(MAKE) lab-down; exit $$status

verify-audit:
	python3 -c "import sys; sys.path.insert(0,'.'); from audit import verify_chain; \
		sys.exit(0 if verify_chain(sys.argv[1]) else 1)" $(AUDIT_DIR) \
		&& echo "audit chain OK" || echo "AUDIT CHAIN BROKEN"
