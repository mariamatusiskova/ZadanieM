class Packet:
    # tag for remove the '!'
    yaml_tag = u'tag:yaml.org,2002:map'

    # kwargs for various length of properties
    def __init__(self, **kwargs):
        self.kwargs = kwargs

    # data to yaml
    @classmethod
    def to_yaml(cls, representer, node):
        for key, value in list(node.kwargs.items()):
            if value is None:
                node.kwargs.pop(key)
        return representer.represent_mapping(cls.yaml_tag, node.kwargs)

    @classmethod
    def from_yaml(cls, constructor, node):
        data = constructor.construct_mapping(node, deep=True)
        return cls(**data)
