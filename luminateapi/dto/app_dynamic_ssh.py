from .common import *


class Tag:
    def __init__(self, key, value):
        self.key = key
        self.value = value

    def to_dict(self):
        return {"key": from_str(self.key),
                "value": from_str(self.value)}


class Vpc:
    def __init__(self, id, vpc, region, cidr_block, integration_id, integration_name):
        self.id = id
        self.vpc = vpc
        self.region = region
        self.cidr_block = cidr_block
        self.integration_id = integration_id
        self.integration_name = integration_name

    def to_dict(self):
        return {"id": from_str(self.id),
                "vpc": from_str(self.vpc),
                "region": from_str(self.region),
                "cidr_block": from_str(self.cidr_block),
                "integration_id": str(self.integration_id),
                "integration_name": from_str(self.integration_name)}


class CloudIntegrationData:
    def __init__(self, tags, segment_id, vpcs):
        self.tags = tags
        self.segment_id = segment_id
        self.vpcs = vpcs

    def to_dict(self):
        return {"tags": from_list(lambda x: to_class(Tag, x), self.tags),
                "segmentId": str(self.segment_id),
                "vpcs": from_list(lambda x: to_class(Vpc, x), self.vpcs)}
