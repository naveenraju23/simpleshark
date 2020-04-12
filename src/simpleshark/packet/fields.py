class Field(object):

    def __init__(self, xml, field_type='Field'):
        self.TYPE = field_type
        self.properties = dict()
        self.fields = []
        self._update_field_info(xml)

    def _update_field_info(self, xml):
        for k, v in xml.attrib.items():
            self.properties[k] = v
        self.add_fields(xml)

    def add_fields(self, xml):
        for x in xml.findall('field'):
            field = Field(x)
            self.fields.append(field)

        for x in xml.findall('proto'):
            field = Field(x, 'Proto')
            self.fields.append(field)

    def get_fields(self):
        return self.fields

    def get_field_names(self):
        return [x.name for x in self.fields]

    def get_multiple_fields(self, field_name):
        """
        Returns a list of all the layers in the packet that are of the layer type (an incase-sensitive string).
        This is in order to retrieve layers which appear multiple times in the same packet (i.e. double VLAN) which cannot be
        retrieved by easier means.
        """
        return [field for field in self.fields if field.name.lower() == field_name.lower()]

    def __repr__(self):
        try:
            return '<%s %s : %s>' % (self.TYPE, self.name, self.value)
        except AttributeError:
            return '<%s %s>' % (self.TYPE, self.name)

    def __contains__(self, field_name):
        """
        Checks if the field is inside the packet.

        :param field: name of the field
        """
        try:
            self[field_name]
            return True
        except KeyError:
            return False

    def __getattr__(self, attr):
        """
        Allows layers to be retrieved via get attr. For instance: pkt.ip
        """
        for field in self.fields:
            if field.name.lower() == attr.lower():
                return field

        raise AttributeError("No attribute named %s" % attr)

    def __getitem__(self, index):
        """
        Allows field items to be retrieved.
        """
        if isinstance(index, int):
            return self.fields[index]
        for field in self.fields:
            if field.name.lower() == index.lower():
                return field
        raise KeyError('Protocol does not exist in packet')

    def sanitize_name(self, name):
        """
        Remove spaces, colons to be able to do a getattr on sub fields.
        Some protocols have _elemen, _field subscripts added like s1-ap, ngap telecom protocols.
        """
        name = name.split('.')[-1]
        if '_element' in name:
            return name.replace('_element', '')
        return name.replace(' ', '_').replace(':', '_').replace('-', '_')

    @property
    def name(self):
        _name = self.properties['name']
        if not _name:
            _name = self.properties['show']
        return self.sanitize_name(_name)

    @property
    def value(self):
        if self.TYPE == 'Field':
            if self.properties['show']:
                return self.properties['show']
            return super(Field, self).__getattr__('value')
        raise AttributeError("No attribute named %s" % 'value')

    @property
    def showname(self):
        return self.properties['showname']

    @property
    def raw(self):
        """
        Raw value is returned. The value is mostly Hex
        """
        return self.properties['value']

    @property
    def size(self):
        return self.properties['size']

    def __len__(self):
        return self.properties['size']

    def _get_subtree_fields(self, parent, subtree_fields):
        for field in self.fields:
            if parent:
                _parent = '.'.join([parent, field.name])
            else:
                _parent = field.name
            _parent = '.'.join([parent, field.name]) if parent else field.name
            subtree_fields[_parent] = field
            if field.fields:
                field._get_subtree_fields(_parent, subtree_fields)

    def get_subtree_fields(self):
        subtree_fields = dict()
        self._get_subtree_fields('', subtree_fields)
        return subtree_fields

    def get_field_value(self, name, raw=False):
        if self.TYPE == 'Proto':
            for field in self.fields:
                if field.name == name and not raw:
                    return getattr(field, 'show', None)
                elif field.name == name and raw:
                    return getattr(field, 'value', None)

