import ast


class WhileTrueNodeToBoundedForTransformer(ast.NodeTransformer):
    def __init__(self, iter_count=3, replace_decendents=False):
        super()
        self.iter_count = iter_count
        self.replace_decendents = replace_decendents

    def visit_FunctionDef(self, node):
        """
        Transform first level while True statements
        to bounded for in range statements.
        """
        self._apply_to_while_in_body(node)
        return node

    def transform_while_to_bounded_for(self, node):

        rng_expr = ast.Call(func=ast.Name(id='range', ctx=ast.Load()), keywords=[],
                            args=[ast.Constant(value=self.iter_count, kind=None)])
        for_node = ast.For(target=ast.Name(id='i', ctx=ast.Store()),
                           orelse=[],
                           iter=rng_expr, body=[ast.Pass()])
        if node.test.value == True:
            if self.replace_decendents:
                node = self._apply_to_while_in_body(node)

            for_node.body = node.body
            return for_node
        else:
            return node

    def _apply_to_while_in_body(self, node):
        for i, n in enumerate(node.body):
            if isinstance(n, ast.While):
                if self.replace_decendents:
                    node.body[i] = self._apply_to_while_in_body(n)
                node.body[i] = self.transform_while_to_bounded_for(n)
        return node
