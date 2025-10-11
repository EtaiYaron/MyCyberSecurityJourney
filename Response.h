#pragma once
#include <string>
using namespace std;

template <typename T>
class Response
{
private:
    string errorMessage;
    T returnValue;

public:
    Response();
    Response(string);
    Response(string, T);

    string getErrorMessage();
    void setErrorMessage(string);

    T getReturnValue();
    void setReturnValue(T);
};

template <typename T>
Response<T>::Response() {}

template <typename T>
Response<T>::Response(string errorMessage) {
    this->errorMessage = errorMessage;
}

template <typename T>
Response<T>::Response(string errorMessage, T returnValue) {
    this->errorMessage = errorMessage;
    this->returnValue = returnValue;
}

template <typename T>
string Response<T>::getErrorMessage() {
    return this->errorMessage;
}

template <typename T>
void Response<T>::setErrorMessage(string value) {
    this->errorMessage = value;
}

template <typename T>
T Response<T>::getReturnValue() {
    return this->returnValue;
}

template <typename T>
void Response<T>::setReturnValue(T value) {
    this->returnValue = value;
}