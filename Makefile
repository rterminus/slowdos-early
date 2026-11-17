features:
	python src/pcap_to_packets.py
	python src/run_pipeline.py
	python src/qa.py

testbed:
	chmod +x testbed/orchestrate.sh
	cd testbed && sudo ./orchestrate.sh