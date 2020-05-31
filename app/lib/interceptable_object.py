class InterceptableObject(object):
    def __setattr__(self, name, value):
        # Instead of assigning a field for each event handler
        # we put them all in this map and call them dynamically.
        if name.startswith("on_"):
            self.event_handlers[name] = value

        super().__setattr__(name, value)

    def __getattr__(self, name):
        if name.startswith("on_"):
            if name in self.event_handlers:
                return self.event_handlers[name]
            else:
                return None
