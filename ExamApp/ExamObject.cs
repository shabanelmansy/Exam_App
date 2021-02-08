using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace ExamApp
{
    class ExamObject
    {
        public void saveExam(string msg)
        {
            if (msg == "close")
                Application.Exit();
        }
    }
}
