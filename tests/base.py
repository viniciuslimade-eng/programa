import os
import shutil
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
FIXTURES = RAIZ / "tests" / "fixtures"
FALSAS = RAIZ / "tests" / "ferramentas_falsas"


class CasoComTmp(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="esteira-teste-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self._path_original = os.environ.get("PATH", "")
        self.addCleanup(os.environ.__setitem__, "PATH", self._path_original)

    def usar_ferramentas_falsas(self):
        os.environ["PATH"] = f"{FALSAS}{os.pathsep}{self._path_original}"
