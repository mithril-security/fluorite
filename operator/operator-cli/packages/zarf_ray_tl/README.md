# ZARF RAY

Deploys Ray on a running cluster with Open-WebUI (available at https://chat.example.com).

In this configuration the inference is spread across two nodes, each with one GPU. Depending on your cluster configuration you may want to change this, and it's enough to modify [ray-service.yaml](./ray-service.yaml). 
```
tensor_parallel_size: 1
pipeline_parallel_size: 2
```

Notice that `workerGroupSpecs.spec.replicas = 2`, because there are two nodes in this configuration.
