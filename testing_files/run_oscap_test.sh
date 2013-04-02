#!/bin/bash

#oscap xccdf eval --profile xccdf_com.example_profile_my_profile --remediate --results=testing_results2.xml testing_ds.xml

oscap xccdf eval --datastream-id=scap_org.open-scap_datastream_tst --xccdf-id=scap_org.open-scap_cref_first-xccdf.xml --profile xccdf_com.example_profile_my_profile --remediate --results=testing_results.xml testing_ds.xml
