import pytest
import app.lib.submission as submission
import app.lab1 as lab1

test_module_path = "/workspaces/2020-lab1/app/lab1/submissions/2020/1111_2222_lab1.py"
submissions_iter = [submission.Submission.from_module_path(test_module_path)]


def get_test_id(submission_val):
    return str(submission_val)


@pytest.mark.parametrize('submission', submissions_iter, ids=get_test_id)
class TestUserHandling:
    @pytest.mark.parent
    def test_login(self, submission):
        pass

    @pytest.mark.child
    def test_modification(self, submission):
        assert 0

    @pytest.mark.parent
    def test_deletion(self, submission):
        pass
    
    @pytest.mark.child
    def test_sklol(self, submission):
        pass
    
    @pytest.mark.child
    def test_delet(self, submission):
        pass
