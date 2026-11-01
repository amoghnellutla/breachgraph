"""Route styles real projects use beyond decorators and router calls."""

from pathlib import Path

from breachgraph.graph.sources.auth import annotate
from breachgraph.graph.sources.routes import routes_in_file
from tests.test_entry_points import write


def routes(tmp: Path, name: str, code: str) -> dict[str, tuple[str, str]]:
    write(tmp, name, code)
    found = routes_in_file(tmp / name, name)
    annotate(found, code)
    return {r.path: (r.method, r.auth) for r in found}


def test_django_rest_framework(tmp_path: Path) -> None:
    code = """from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated, AllowAny

class DocViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]

    def create(self, request):
        return 1

    @action(detail=True, methods=["post"])
    def share(self, request, pk=None):
        return 2

    def helper(self):
        return 3

class PublicView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        return 4

class NotAView:
    def get(self):
        return 5
"""
    assert routes(tmp_path, "views.py", code) == {
        "/DocViewSet/create": ("POST", "IsAuthenticated"),
        "/DocViewSet/share": ("ANY", "IsAuthenticated"),
        "/PublicView/get": ("GET", ""),
    }


def test_flask_method_view_and_add_url_rule(tmp_path: Path) -> None:
    code = """class Users(MethodView):
    def get(self):
        return 1

app.add_url_rule("/users", view_func=Users.as_view("users"))
"""
    found = routes(tmp_path, "a.py", code)
    assert found["/Users/get"][0] == "GET" and "/users" in found


def test_jaxrs(tmp_path: Path) -> None:
    code = """import javax.ws.rs.*;

@Path("/users")
public class UserResource {
    @GET
    @Path("{id}")
    public String get(@PathParam("id") String id) { return id; }

    @POST
    @RolesAllowed("admin")
    public String add(String body) { return body; }

    public void helper() {}
}
"""
    assert routes(tmp_path, "UserResource.java", code) == {
        "/users/{id}": ("GET", ""),
        "/users": ("POST", "RolesAllowed"),
    }


def test_trpc(tmp_path: Path) -> None:
    code = """export const appRouter = router({
  hello: publicProcedure.query(() => 'hi'),
  me: protectedProcedure.input(z.string()).query(async ({ input }) => load(input)),
  save: authedProcedure.input(z.string()).mutation(async ({ input }) => store(input)),
  config: { nested: true },
})
"""
    assert routes(tmp_path, "router.ts", code) == {
        "/trpc/hello": ("POST", ""),
        "/trpc/me": ("POST", "protectedProcedure"),
        "/trpc/save": ("POST", "authedProcedure"),
    }
