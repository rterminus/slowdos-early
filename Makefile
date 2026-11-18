features:
	python src/pcap_to_packets.py
	python src/run_pipeline.py
	python src/qa.py

testbed:
	chmod +x testbed/orchestrate.sh
	cd testbed && sudo ./orchestrate.sh

.PHONY: hoeffding-tree
hoeffding-tree:
	python src/hoeffding_tree_pipeline.py \
		--data data/processed/flows_n8_v1.csv \
		--output results/hoeffding_tree