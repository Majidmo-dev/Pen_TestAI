.PHONY: lab-up lab-down run eval verify-audit

lab-up:
	docker compose up -d dvwa

lab-down:
	docker compose down -v

run: lab-up
	docker compose run --rm agent python main.py --target dvwa
	$(MAKE) lab-down

eval:
	docker compose run --rm agent python eval.py --all

verify-audit:
	python3 -c "import sys; sys.path.insert(0,'.'); from audit import AuditLog; \
		a = AuditLog(sys.argv[1]); sys.exit(0 if a.verify() else 1)" $(AUDIT_DIR) \
		&& echo "audit chain OK" || echo "AUDIT CHAIN BROKEN"
