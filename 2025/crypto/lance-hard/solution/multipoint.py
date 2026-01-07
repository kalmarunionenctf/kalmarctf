from sage.all import *

class multi_point_tree:
    def __init__(self, X, points: list):
        self.n_points = len(points)
        if self.n_points == 0:
            self.vanishing = 1

        elif self.n_points == 1:
            self.vanishing = X - points[0]
            self.point = points[0]

        else:
            mid = (self.n_points + 1) // 2
            self.left = multi_point_tree(X, points[:mid])
            self.right = multi_point_tree(X, points[mid:])
            self.vanishing = self.left.vanishing * self.right.vanishing

    def evaluate(self, poly):
        if self.n_points == 0:
            return []
        elif self.n_points == 1:
            return [poly(self.point)]
        else:
            poly = poly % self.vanishing
            return self.left.evaluate(poly) + self.right.evaluate(poly)

    def _evaluate_inv_derivative(self, poly):
        if self.n_points == 0:
            pass
        elif self.n_points == 1:
            self.inv_derivative = poly(self.point).inverse()
        else:
            poly = poly % self.vanishing
            self.left._evaluate_inv_derivative(poly)
            self.right._evaluate_inv_derivative(poly)

    # Evaluates the derivatives of the vanishing polynomial at all points. Must be called before
    # running interpolate(), and both functions must only be run on the root.
    def calculate_derivatives(self):
        self._evaluate_inv_derivative(self.vanishing.derivative())

    def interpolate(self, points_y: list):
        assert len(points_y) == self.n_points

        if self.n_points == 0:
            return 0
        elif self.n_points == 1:
            return self.inv_derivative * points_y[0]
        else:
            points_y_left = points_y[:self.left.n_points]
            points_y_right = points_y[self.left.n_points:]
            return (self.left.interpolate(points_y_left) * self.right.vanishing +
                    self.right.interpolate(points_y_right) * self.left.vanishing)
